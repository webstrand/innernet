use crate::data_store::DataStore;
use bytes::{Buf, Bytes};
use innernet_shared::{
    cbor,
    interface_config::{InterfaceConfig, ServerInfo},
    media_type, parent_cidr,
    problem::{self, Problem},
    smallest_cidr_holding, tls, wg, Association, Cidr, CidrDeletion, LegacyAssociation,
    LegacyAssociationContents, LegacyCapabilities, LegacyCidr, LegacyCidrContents, LegacyPeer,
    LegacyPeerContents, LegacyState, PeerContents, PeerUpdate, Prefix, State, TaggedCidr,
    TaggedPeer, TaggedPeerDelegations, INNERNET_PUBKEY_HEADER,
};
use quinn::crypto::rustls::QuicClientConfig;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    cell::Cell,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use wireguard_control::InterfaceName;

/// How long the client waits for the server, in plain HTTP and over QUIC. Some platforms, such as
/// OpenBSD, can take longer to complete the first WireGuard handshake, so a lower timeout could
/// fail a request that would succeed.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Records something that the client learned about the server in the data store.
type Recorder<'a, T> = Box<dyn Fn(T) -> Result<(), anyhow::Error> + 'a>;

/// A REST client that can be used to communicate with an innernet REST server.
///
/// Requests are made to the TLS API, in HTTP/3 over QUIC at the server's internal address,
/// authenticated with the interface's WireGuard key. The internal address is the primary IP that
/// the coordinator's peer states in the data store, as every peer's is; the interface config's
/// internal endpoint is read only while the data store doesn't record the coordinator, at
/// installation. The client needs the QUIC port of the API, which the invitation states, or the
/// data store records; without one, the client asks the server for it in plain HTTP. A server
/// that states no port, as servers that predate TLS do, is sent the requests in plain HTTP
/// instead, unless the server is known to speak TLS. The server becomes known to speak TLS when
/// it first answers over QUIC, and from then on the client refuses plain HTTP for its requests,
/// and asks for the port only. When the server doesn't answer at the port, the client asks it
/// for the port once more, since the operator may have moved it.
///
/// We recommend to use the high level API (like [`Self::create_peer()`]) when possible and fall
/// back on the low level [`Self::http()`] and [`Self::http_form()`] otherwise.
pub struct RestClient<'a> {
    plain_client: hyper::Client<hyper::client::HttpConnector>,
    tls_config: Arc<quinn::rustls::ClientConfig>,
    server: &'a ServerInfo,
    /// The server's internal address, at which the client reaches its API.
    address: IpAddr,
    /// The QUIC port of the server's TLS API, if known.
    quic_port: Cell<Option<u16>>,
    /// Whether the client has asked the server for the QUIC port, which it does at most once.
    asked_port: Cell<bool>,
    /// Whether the server is known to speak TLS, in which case the client never falls back to
    /// plain HTTP.
    speaks_tls: Cell<bool>,
    /// Whether the server stated no QUIC port, as servers that predate TLS do, after which the
    /// client makes its requests in plain HTTP.
    predates_tls: Cell<bool>,
    /// Records for good that the server speaks TLS, when it first answers over QUIC.
    latch: Option<Recorder<'a, ()>>,
    /// Records the QUIC port that the server stated, when the client asked it for the port.
    record_port: Option<Recorder<'a, u16>>,
    /// How long the client waits for the server.
    timeout: Duration,
    /// The interface that carries the requests, whose MTU must carry QUIC, if known.
    interface: Option<InterfaceName>,
}

impl<'a> RestClient<'a> {
    /// Create a [`Self`] to communicate with the innernet server of an interface, as the
    /// interface's peer. `speaks_tls` is whether the server is known to speak TLS. Nothing
    /// records it if the server answers over QUIC; [`Self::speaks_tls`] tells whether it did. The
    /// QUIC port is the one that the interface config states, if any.
    pub fn new(config: &'a InterfaceConfig, speaks_tls: bool) -> Result<Self, RestError> {
        let tls_config =
            tls::client_config(&config.interface.private_key, &config.server.public_key)
                .map_err(RestError::TlsConfig)?;
        Ok(Self {
            plain_client: hyper::Client::builder().build_http(),
            tls_config,
            server: &config.server,
            address: config.server.internal_endpoint.ip(),
            quic_port: Cell::new(config.server.quic_port),
            asked_port: Cell::new(false),
            speaks_tls: Cell::new(speaks_tls),
            predates_tls: Cell::new(false),
            latch: None,
            record_port: None,
            timeout: TIMEOUT,
            interface: None,
        })
    }

    /// The client, whose requests `interface` carries, so that a request over QUIC fails clearly
    /// when the MTU of the interface is too small for QUIC.
    pub fn on_interface(self, interface: &InterfaceName) -> Self {
        Self {
            interface: Some(*interface),
            ..self
        }
    }

    /// Create a [`Self`] to communicate with the innernet server of `interface`, whose data store
    /// records whether the server is known to speak TLS, and the QUIC port of its TLS API, if the
    /// client has learned it from the server. The data store records that the server speaks TLS
    /// when the server first answers over QUIC, and the port when the server states one. The
    /// client reaches the server at the primary IP of the coordinator's peer in the data store,
    /// or, while the data store doesn't record the coordinator, at the internal endpoint of the
    /// interface config.
    pub fn for_interface(
        config: &'a InterfaceConfig,
        data_dir: &'a Path,
        interface: &'a InterfaceName,
    ) -> Result<Self, RestError> {
        let server_key = &config.server.public_key;
        let (speaks_tls, quic_port, address) = DataStore::open(data_dir, interface, config)
            .and_then(|store| {
                Ok((
                    store.speaks_tls(server_key)?,
                    store.quic_port(server_key)?,
                    store.coordinator(config)?.0,
                ))
            })
            .map_err(RestError::DataStore)?;
        let client = Self {
            address,
            ..Self::new(config, speaks_tls)?.on_interface(interface)
        };
        client.quic_port.set(quic_port.or(config.server.quic_port));
        // A data store that the client first made without an invitation records the coordinator
        // only once the server reports it, after which `fetch` records what the client learned.
        let open = move || -> Result<Option<DataStore>, anyhow::Error> {
            let store = DataStore::open(data_dir, interface, config)?;
            Ok(store.records_peer(server_key)?.then_some(store))
        };
        Ok(Self {
            latch: Some(Box::new(move |()| match open()? {
                Some(mut store) => store.latch_tls(server_key),
                None => Ok(()),
            })),
            record_port: Some(Box::new(move |port| match open()? {
                Some(mut store) => store.set_quic_port(server_key, port),
                None => Ok(()),
            })),
            ..client
        })
    }

    /// Whether the server is known to speak TLS, either from the start or because it has
    /// answered this client over QUIC.
    pub fn speaks_tls(&self) -> bool {
        self.speaks_tls.get()
    }

    /// The QUIC port of the server's TLS API, if the client knows it.
    pub fn quic_port(&self) -> Option<u16> {
        self.quic_port.get()
    }

    /// The server's internal address, at which the client reaches its API.
    pub fn address(&self) -> IpAddr {
        self.address
    }

    /// Creates the CIDR `cidr`, under the parent that its prefix gives it, and returns it as the
    /// server created it. A server in plain HTTP is sent the ID of the parent, the smallest of
    /// its CIDRs that holds `cidr`, and returns the CIDR with its ID, which is left out.
    pub async fn create_cidr(&self, cidr: &Cidr) -> Result<Cidr, RestError> {
        match self.admin_api().await? {
            AdminApi::ByKey => self.http_form("POST", "/admin/cidrs", cidr).await,
            AdminApi::Legacy => {
                let cidrs = self.get_legacy_cidrs().await?;
                let prefixes: Vec<Prefix> = cidrs.iter().map(|cidr| cidr.prefix()).collect();
                let parent = parent_cidr(&cidr.cidr, &prefixes)
                    .map(|parent| legacy_cidr_id(&cidrs, &parent))
                    .transpose()?;
                let contents = LegacyCidrContents {
                    name: cidr.name.clone(),
                    cidr: cidr.cidr.net(),
                    parent,
                };
                let created: LegacyCidr = self.http_form("POST", "/admin/cidrs", contents).await?;
                Ok(created.into())
            },
        }
    }

    /// Lists every CIDR of the network. A server in plain HTTP lists the CIDRs with their IDs and
    /// the IDs of their parents, which are left out: the parent of a CIDR is the smallest other
    /// CIDR that holds it.
    pub async fn get_cidrs(&self) -> Result<Vec<Cidr>, RestError> {
        let (transport, body) = self.request_raw::<()>("GET", "/admin/cidrs", None).await?;
        match transport {
            Transport::Tls => decode(transport, &body),
            Transport::Plain => decode::<Vec<LegacyCidr>>(transport, &body)
                .map(|cidrs| cidrs.into_iter().map(Cidr::from).collect()),
        }
    }

    /// Lists every CIDR of the network as a server in plain HTTP lists them, with their IDs.
    async fn get_legacy_cidrs(&self) -> Result<Vec<LegacyCidr>, RestError> {
        self.http("GET", "/admin/cidrs").await
    }

    /// Reads the CIDR `listed` and its tag in the API of TLS sessions, as long as the CIDR is
    /// still as it was listed. A CIDR that has changed since it was listed is refused as
    /// [`RestError::CidrChanged`], and one that the server doesn't hold as
    /// [`RestError::NoSuchCidr`].
    pub async fn get_tagged_cidr(&self, listed: &Cidr) -> Result<TaggedCidr, RestError> {
        let path = format!("/admin/cidrs/{}", listed.cidr.api_path_segment());
        let tagged: TaggedCidr = self.http("GET", &path).await?;
        if tagged.cidr != *listed {
            return Err(RestError::CidrChanged);
        }
        Ok(tagged)
    }

    /// Renames the CIDR `listed`, as it was listed, to `name`. A CIDR that the server doesn't
    /// hold is refused as [`RestError::NoSuchCidr`]. In the API of TLS sessions, a CIDR that has
    /// changed since it was listed is refused as [`RestError::CidrChanged`]: the client refuses
    /// it when it reads it with its tag, and the server refuses it if it changes between the read
    /// and the rename. A server in plain HTTP names the CIDR by an ID, so the client lists the
    /// CIDRs again for the ID of the CIDR with the prefix of `listed`.
    pub async fn rename_cidr(&self, listed: &Cidr, name: &str) -> Result<(), RestError> {
        match self.admin_api().await? {
            AdminApi::ByKey => {
                let TaggedCidr { tag, .. } = self.get_tagged_cidr(listed).await?;
                let path = format!("/admin/cidrs/{}", listed.cidr.api_path_segment());
                let renamed = TaggedCidr {
                    cidr: Cidr {
                        name: name.to_string(),
                        cidr: listed.cidr,
                    },
                    tag,
                };
                self.http_form("PUT", &path, renamed).await
            },
            AdminApi::Legacy => {
                let cidrs = self.get_legacy_cidrs().await?;
                let legacy = cidrs
                    .iter()
                    .find(|legacy| legacy.prefix() == listed.cidr)
                    .ok_or(RestError::NoSuchCidr)?;
                let contents = LegacyCidrContents {
                    name: name.to_string(),
                    ..legacy.contents.clone()
                };
                self.http_form("PUT", &format!("/admin/cidrs/{}", legacy.id), contents)
                    .await
            },
        }
    }

    /// Deletes the CIDR `listed`, as it was listed, which must have neither peers nor children.
    /// A CIDR that the server doesn't hold is refused as [`RestError::NoSuchCidr`], and in the
    /// API of TLS sessions, one that has changed since it was listed as
    /// [`RestError::CidrChanged`], as [`Self::rename_cidr`] refuses it.
    pub async fn delete_cidr(&self, listed: &Cidr) -> Result<(), RestError> {
        match self.admin_api().await? {
            AdminApi::ByKey => {
                let TaggedCidr { tag, .. } = self.get_tagged_cidr(listed).await?;
                let path = format!("/admin/cidrs/{}", listed.cidr.api_path_segment());
                self.http_form("DELETE", &path, CidrDeletion { tag }).await
            },
            AdminApi::Legacy => {
                let path = format!(
                    "/admin/cidrs/{}",
                    legacy_cidr_id(&self.get_legacy_cidrs().await?, &listed.cidr)?
                );
                self.http("DELETE", &path)
                    .await
                    .map_err(|e| e.not_found_as(RestError::NoSuchCidr))
            },
        }
    }

    /// Lists every association of the network. A server in plain HTTP names the CIDRs of each
    /// association by ID, so the client lists the CIDRs too, for their prefixes.
    pub async fn get_associations(&self) -> Result<Vec<Association>, RestError> {
        let (transport, body) = self
            .request_raw::<()>("GET", "/admin/associations", None)
            .await?;
        match transport {
            Transport::Tls => decode(transport, &body),
            Transport::Plain => {
                let associations: Vec<LegacyAssociation> = decode(transport, &body)?;
                let cidrs = self.get_legacy_cidrs().await?;
                let prefix = |id: i64| {
                    cidrs
                        .iter()
                        .find(|cidr| cidr.id == id)
                        .map(|cidr| cidr.prefix())
                        .ok_or(RestError::NoSuchCidr)
                };
                associations
                    .iter()
                    .map(|association| {
                        Ok(Association {
                            cidr_1: prefix(association.cidr_id_1)?,
                            cidr_2: prefix(association.cidr_id_2)?,
                        })
                    })
                    .collect()
            },
        }
    }

    /// Associates the CIDRs of `association`. A server in plain HTTP names the CIDRs by ID, so
    /// the client lists the CIDRs for their IDs.
    pub async fn create_association(&self, association: &Association) -> Result<(), RestError> {
        match self.admin_api().await? {
            AdminApi::ByKey => {
                self.http_form("POST", "/admin/associations", association)
                    .await
            },
            AdminApi::Legacy => {
                let cidrs = self.get_legacy_cidrs().await?;
                let contents = LegacyAssociationContents {
                    cidr_id_1: legacy_cidr_id(&cidrs, &association.cidr_1)?,
                    cidr_id_2: legacy_cidr_id(&cidrs, &association.cidr_2)?,
                };
                self.http_form("POST", "/admin/associations", contents)
                    .await
            },
        }
    }

    /// Deletes the association of the CIDRs of `association`, in either order. An association
    /// that the server doesn't hold is refused as [`RestError::NoSuchAssociation`]. A server in
    /// plain HTTP names an association by ID, so the client lists the associations and the CIDRs
    /// again for its ID.
    pub async fn delete_association(&self, association: &Association) -> Result<(), RestError> {
        match self.admin_api().await? {
            AdminApi::ByKey => {
                self.http(
                    "DELETE",
                    &format!("/admin/associations/{}", association.api_path()),
                )
                .await
            },
            AdminApi::Legacy => {
                let cidrs = self.get_legacy_cidrs().await?;
                let (id_1, id_2) = (
                    legacy_cidr_id(&cidrs, &association.cidr_1)?,
                    legacy_cidr_id(&cidrs, &association.cidr_2)?,
                );
                let associations: Vec<LegacyAssociation> =
                    self.http("GET", "/admin/associations").await?;
                let listed = associations
                    .iter()
                    .find(|listed| {
                        (listed.cidr_id_1, listed.cidr_id_2) == (id_1, id_2)
                            || (listed.cidr_id_1, listed.cidr_id_2) == (id_2, id_1)
                    })
                    .ok_or(RestError::NoSuchAssociation)?;
                self.http("DELETE", &format!("/admin/associations/{}", listed.id))
                    .await
                    .map_err(|e| e.not_found_as(RestError::NoSuchAssociation))
            },
        }
    }

    /// Creates a peer, and returns it as the server created it. A server in plain HTTP is sent the
    /// peer as clients that predate TLS know it, with the ID of its CIDR, the smallest of the
    /// server's CIDRs that holds its address, and returns the peer with its ID, which is left
    /// out. A peer that such clients can't represent is refused without a request: one without a
    /// name as [`RestError::NamelessUnsupported`], and one whose delegations are anything but a
    /// single address as [`RestError::DelegationsUnsupported`].
    pub async fn create_peer(
        &self,
        peer_contents: &PeerContents,
    ) -> Result<PeerContents, RestError> {
        match self.admin_api().await? {
            AdminApi::ByKey => self.http_form("POST", "/admin/peers", peer_contents).await,
            AdminApi::Legacy => {
                if peer_contents.name.is_none() {
                    return Err(RestError::NamelessUnsupported);
                }
                let [address] = &peer_contents.delegations[..] else {
                    return Err(RestError::DelegationsUnsupported);
                };
                if !address.is_host() {
                    return Err(RestError::DelegationsUnsupported);
                }
                let cidrs = self.get_legacy_cidrs().await?;
                let prefixes: Vec<Prefix> = cidrs.iter().map(|cidr| cidr.prefix()).collect();
                let cidr =
                    smallest_cidr_holding(address, &prefixes).ok_or(RestError::NoSuchCidr)?;
                let legacy =
                    LegacyPeerContents::from_peer(peer_contents, legacy_cidr_id(&cidrs, &cidr)?)
                        .ok_or(RestError::DelegationsUnsupported)?;
                let peer: LegacyPeer = self.http_form("POST", "/admin/peers", legacy).await?;
                Ok(peer.contents.into())
            },
        }
    }

    /// The state of the network as this peer sees it. A server in plain HTTP sends the peers with
    /// their IDs, which are left out.
    pub async fn get_state(&self) -> Result<State, RestError> {
        let (transport, body) = self.request_raw::<()>("GET", "/user/state", None).await?;
        match transport {
            Transport::Tls => decode(transport, &body),
            Transport::Plain => decode::<LegacyState>(transport, &body).map(State::from),
        }
    }

    /// Lists every peer of the network. A server in plain HTTP lists the peers with their IDs,
    /// which are left out.
    pub async fn get_peers(&self) -> Result<Vec<PeerContents>, RestError> {
        let (transport, body) = self.request_raw::<()>("GET", "/admin/peers", None).await?;
        match transport {
            Transport::Tls => decode(transport, &body),
            Transport::Plain => decode::<Vec<LegacyPeer>>(transport, &body)
                .map(|peers| peers.into_iter().map(|peer| peer.contents.into()).collect()),
        }
    }

    /// Lists every peer of the network as a server in plain HTTP lists them, with their IDs.
    pub async fn get_legacy_peers(&self) -> Result<Vec<LegacyPeer>, RestError> {
        self.http("GET", "/admin/peers").await
    }

    /// The admin API that the server offers this client. Unless the client knows that the server
    /// speaks TLS, or knows the QUIC port of its TLS API, it asks the server for the port, which
    /// settles whether the client speaks TLS or plain HTTP to the server.
    pub async fn admin_api(&self) -> Result<AdminApi, RestError> {
        if !self.speaks_tls.get() && !self.predates_tls.get() {
            self.tls_port().await?;
        }
        Ok(if self.predates_tls.get() {
            AdminApi::Legacy
        } else {
            AdminApi::ByKey
        })
    }

    /// Reads the peer `listed` and its tag in the API of TLS sessions, as long as the peer is
    /// still as it was listed, but for its endpoint and candidates, which the peer reports on its
    /// own, and its delegations, which an admin changes apart from the rest of the peer. A peer
    /// that has changed since it was listed is refused as
    /// [`RestError::PeerChanged`]. A peer that the server does not find by its key, since it has
    /// been deleted or its key has changed, as a redeemed invitation's does, is refused as
    /// [`RestError::NoSuchPeer`].
    pub async fn get_tagged_peer(&self, listed: &PeerContents) -> Result<TaggedPeer, RestError> {
        let path = format!("/admin/peers/{}", listed.api_path_segment());
        let tagged: TaggedPeer = self.http("GET", &path).await?;
        if !same_but_untagged(&tagged.peer, listed) {
            return Err(RestError::PeerChanged);
        }
        Ok(tagged)
    }

    /// The peer `listed` as a server in plain HTTP lists it, with the ID by which it names the
    /// peer, as long as the peer is still as it was listed, but for what
    /// [`Self::get_tagged_peer`] leaves out. The client keeps no IDs, so it lists the peers again, and takes the peer with the public
    /// key of `listed`. A peer that has changed since it was listed, or is gone, is refused as
    /// [`RestError::PeerChanged`].
    async fn get_legacy_peer(&self, listed: &PeerContents) -> Result<LegacyPeer, RestError> {
        self.get_legacy_peers()
            .await?
            .into_iter()
            .find(|peer| peer.public_key == listed.public_key)
            .filter(|peer| same_but_untagged(&peer.contents.clone().into(), listed))
            .ok_or(RestError::PeerChanged)
    }

    /// Applies an admin's changes to the peer `listed`, as it was listed: its name, its admin
    /// role and whether it is disabled are set to those of `contents`. A peer that has changed
    /// since it was listed is refused as [`RestError::PeerChanged`]: in the API of TLS sessions,
    /// the server refuses it, and with a server in plain HTTP, which can't, the client refuses
    /// it before the change, as far as it can tell. In the API of TLS sessions, a peer that the
    /// server does not find by its key is refused as [`RestError::NoSuchPeer`]. A server in plain
    /// HTTP can't hold a peer without a name, so a change that removes the name is refused as
    /// [`RestError::NamelessUnsupported`] without a request.
    pub async fn update_peer(
        &self,
        listed: &PeerContents,
        contents: &PeerContents,
    ) -> Result<(), RestError> {
        match self.admin_api().await? {
            AdminApi::ByKey => {
                let TaggedPeer { tag, .. } = self.get_tagged_peer(listed).await?;
                let path = format!("/admin/peers/{}", listed.api_path_segment());
                self.http_form("PUT", &path, PeerUpdate::new(tag, contents))
                    .await
            },
            AdminApi::Legacy => {
                if contents.name.is_none() {
                    return Err(RestError::NamelessUnsupported);
                }
                // The peer is sent as the server lists it, with the changes an admin may make.
                let LegacyPeer { id, contents: peer } = self.get_legacy_peer(listed).await?;
                let legacy = LegacyPeerContents {
                    name: contents.name.clone(),
                    is_admin: contents.is_admin,
                    is_disabled: contents.is_disabled,
                    ..peer
                };
                self.http_form("PUT", &format!("/admin/peers/{id}"), legacy)
                    .await
            },
        }
    }

    /// Replaces the delegations of the peer `listed`, as it was listed, with `delegations` as a
    /// whole, in the API of TLS sessions, and marks `reclaim`, if any, to be reclaimed beside those
    /// of `delegations` that are marked already. Delegations that have changed since the peer was
    /// listed are refused as [`RestError::PeerChanged`]: the client refuses them when it reads
    /// them with their tag, and the server refuses them if they change between the read and the
    /// change. A peer that the server does not find by its key is refused as
    /// [`RestError::NoSuchPeer`]. A server that predates TLS has no delegations, and is refused as
    /// [`RestError::DelegationsUnsupported`] without a request.
    pub async fn set_delegations(
        &self,
        listed: &PeerContents,
        delegations: Vec<Prefix>,
        reclaim: Option<Prefix>,
    ) -> Result<(), RestError> {
        if self.admin_api().await? == AdminApi::Legacy {
            return Err(RestError::DelegationsUnsupported);
        }
        let path = format!("/admin/peers/{}/delegations", listed.api_path_segment());
        let TaggedPeerDelegations {
            delegations: current,
            reclaim: marked,
            tag,
        } = self.http("GET", &path).await?;
        let mut listed_delegations = listed.delegations.clone();
        listed_delegations.sort();
        if current != listed_delegations {
            return Err(RestError::PeerChanged);
        }
        let reclaim = marked
            .into_iter()
            .chain(reclaim)
            .filter(|range| delegations.contains(range))
            .collect();
        self.http_form(
            "PUT",
            &path,
            TaggedPeerDelegations {
                delegations,
                reclaim,
                tag,
            },
        )
        .await
    }

    /// Perform a `verb` HTTP request at the given `endpoint`.
    ///
    /// Example: `rest_client.http("GET", "/admin/peers").await?;`.
    pub async fn http<T: DeserializeOwned>(
        &self,
        verb: &str,
        endpoint: &str,
    ) -> Result<T, RestError> {
        self.request::<(), _>(verb, endpoint, None).await
    }

    /// Send serializable data using a `verb` HTTP request at the given `endpoint`
    ///
    /// Example: `rest_client.http_form("POST", "/admin/peers", PeerContents { .. }).await?;`.
    pub async fn http_form<S: Serialize, T: DeserializeOwned>(
        &self,
        verb: &str,
        endpoint: &str,
        form: S,
    ) -> Result<T, RestError> {
        self.request(verb, endpoint, Some(form)).await
    }

    async fn request<S: Serialize, T: DeserializeOwned>(
        &self,
        verb: &str,
        endpoint: &str,
        form: Option<S>,
    ) -> Result<T, RestError> {
        let (transport, body) = self.request_raw(verb, endpoint, form).await?;
        decode(transport, &body)
    }

    /// Performs a `verb` HTTP request at `endpoint`, with `form` as its body, and returns the
    /// transport that the server answered in, with the body of the answer. The form of the
    /// answer can depend on the transport, since a server in plain HTTP serves the API as clients
    /// that predate TLS know it. The body of the request, and that of the answer, is CBOR over TLS
    /// and JSON in plain HTTP. Over TLS, every request accepts the newest version of the API, the
    /// body of a request states it, and the body of an answer of another version is refused.
    async fn request_raw<S: Serialize>(
        &self,
        verb: &str,
        endpoint: &str,
        form: Option<S>,
    ) -> Result<(Transport, Vec<u8>), RestError> {
        loop {
            if self.predates_tls.get() {
                let body = self.plain_request(verb, endpoint, form.as_ref()).await?;
                return Ok((Transport::Plain, body));
            }
            // Without a port, the server predates TLS, and the request goes in plain HTTP.
            let Some(port) = self.tls_port().await? else {
                continue;
            };
            if let Some(interface) = &self.interface {
                wg::check_quic_mtu(interface, self.address).map_err(RestError::Mtu)?;
            }
            let body = form
                .as_ref()
                .map(cbor::to_vec)
                .transpose()
                .map_err(|e| RestError::RequestSerialize(e.into()))?;
            match self.quic_request(port, verb, endpoint, body).await {
                Ok(answer) => {
                    // The server authenticated with its key and answered over QUIC.
                    self.record_tls();
                    return answer.into_tls_body().map(|body| (Transport::Tls, body));
                },
                // Nothing answered at the port, which the operator may have moved, so the client
                // asks the server for the port, once, and tries again at the port it states.
                Err(e) if e.is_connection_failure() && !self.asked_port.get() => {
                    log::info!(
                        "the TLS API of the innernet server didn't answer at port {port} ({e}), \
                         so the client asks the server for the port."
                    );
                    match self.ask_port().await {
                        Ok(Some(asked)) if asked != port => {},
                        Ok(None) => {},
                        Ok(Some(_)) => return Err(e.into()),
                        Err(RestError::ServerDowngraded) => {
                            return Err(RestError::ServerDowngraded)
                        },
                        Err(_) => return Err(e.into()),
                    }
                },
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// The QUIC port of the server's TLS API, which the client asks the server for if it doesn't
    /// know it, or `None` if the server predates TLS.
    async fn tls_port(&self) -> Result<Option<u16>, RestError> {
        match self.quic_port.get() {
            Some(port) => Ok(Some(port)),
            None => self.ask_port().await,
        }
    }

    /// Asks the server for the QUIC port of its TLS API, in plain HTTP, which the server answers
    /// even once it requires TLS of this client, and records the port that it states. A server
    /// that states none predates TLS: from then on, the client makes its requests in plain HTTP,
    /// unless the server is known to speak TLS, in which case the client refuses to. WireGuard
    /// authenticates the server's internal address, so the client can trust the answer.
    async fn ask_port(&self) -> Result<Option<u16>, RestError> {
        self.asked_port.set(true);
        // A server that predates capabilities answers 404.
        let port = match self
            .plain_request::<()>("GET", "/user/capabilities", None)
            .await
        {
            Ok(body) => decode::<Option<LegacyCapabilities>>(Transport::Plain, &body)?
                .and_then(|capabilities| capabilities.quic_port),
            Err(e) if e.has_status_of(404) => None,
            Err(e) => return Err(e),
        };
        let Some(port) = port else {
            if self.speaks_tls.get() {
                return Err(RestError::ServerDowngraded);
            }
            log::warn!(
                "the innernet server predates TLS, so requests to it are made in plain HTTP, in \
                 which anything on this machine that sends from its innernet IP can act as this \
                 peer, until the server is upgraded."
            );
            self.predates_tls.set(true);
            return Ok(None);
        };
        if self.quic_port.replace(Some(port)) != Some(port) {
            log::info!("the TLS API of the innernet server is at QUIC port {port}.");
            if let Some(record_port) = &self.record_port {
                if let Err(e) = record_port(port) {
                    log::warn!("failed to record the QUIC port of the innernet server: {e:#}");
                }
            }
        }
        Ok(Some(port))
    }

    /// Performs a `verb` request at `endpoint` in plain HTTP, in the API of servers that predate
    /// TLS, with `form` as its JSON body, and returns the body of the answer.
    async fn plain_request<S: Serialize>(
        &self,
        verb: &str,
        endpoint: &str,
        form: Option<&S>,
    ) -> Result<Vec<u8>, RestError> {
        // The API of servers that predate TLS is versioned by the prefix of its paths.
        let server = SocketAddr::new(self.address, self.server.internal_endpoint.port());
        let url = format!("http://{server}/v1{endpoint}");
        let body = form
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|e| RestError::RequestSerialize(e.into()))?;
        let mut request = hyper::Request::builder()
            .method(verb)
            .uri(url)
            .header(INNERNET_PUBKEY_HEADER, &self.server.public_key);
        if body.is_some() {
            request = request.header(hyper::header::CONTENT_TYPE, "application/json");
        }
        let request = request
            .body(body.map_or_else(hyper::Body::empty, hyper::Body::from))
            .map_err(|e| RestError::RequestSerialize(e.into()))?;
        let exchange = async {
            let response = self
                .plain_client
                .request(request)
                .await
                .map_err(|e| RestError::RequestSend(Box::new(e)))?;
            let status = response.status().as_u16();
            if status >= 400 {
                // The server explains refusals that an outdated client can't make sense of.
                let explained = read_limited(response.into_body(), MAX_EXPLANATION_LEN).await;
                let message = explanation(&explained.unwrap_or_default());
                return Err(if message.is_empty() {
                    RestError::Status(status)
                } else {
                    RestError::Refused { status, message }
                });
            }
            let body = read_limited(response.into_body(), MAX_RESPONSE_LEN + 1)
                .await
                .map_err(RestError::ResponseRead)?;
            check_length(&body)?;
            Ok(body)
        };
        tokio::time::timeout(self.timeout, exchange)
            .await
            .map_err(|elapsed| RestError::RequestSend(Box::new(elapsed)))?
    }

    /// Performs a `verb` request at `endpoint` over QUIC, at `port` of the server's internal
    /// address, with `body`, in CBOR, if any, and returns the answer, whatever its status.
    async fn quic_request(
        &self,
        port: u16,
        verb: &str,
        endpoint: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Answer, QuicError> {
        let server = SocketAddr::new(self.address, port);
        // Every request names the version that it reads in Accept, which the server requires of
        // every change, so that it never takes a change for one of another version. A body
        // states its version, and a request without a form carries neither a body nor a content
        // type.
        let mut request = http::Request::builder()
            .method(verb)
            .uri(format!("https://{server}{endpoint}"))
            .header(INNERNET_PUBKEY_HEADER, &self.server.public_key)
            .header(http::header::ACCEPT, media_type::accept());
        if let Some(body) = &body {
            request = request
                .header(
                    http::header::CONTENT_TYPE,
                    media_type::content_type(media_type::VERSION),
                )
                .header(http::header::CONTENT_LENGTH, body.len());
        }
        let request = request
            .body(())
            .map_err(|e| QuicError::Request(e.to_string()))?;
        let crypto = QuicClientConfig::try_from(self.tls_config.clone())
            .map_err(|e| QuicError::Request(e.to_string()))?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(
            self.timeout
                .try_into()
                .map_err(|_| QuicError::Request("the timeout is too long".into()))?,
        ));
        client_config.transport_config(Arc::new(transport));
        exchange(server, client_config, request, body).await
    }

    /// Records that the server speaks TLS, if it isn't known yet.
    fn record_tls(&self) {
        if self.speaks_tls.replace(true) {
            return;
        }
        if let Some(latch) = &self.latch {
            if let Err(e) = latch(()) {
                log::warn!("failed to record that the innernet server speaks TLS: {e:#}");
            }
        }
    }
}

/// Exchanges `request`, with `body`, if any, for an answer, on a connection of its own to
/// `server`, which is closed afterwards.
async fn exchange(
    server: SocketAddr,
    client_config: quinn::ClientConfig,
    request: http::Request<()>,
    body: Option<Vec<u8>>,
) -> Result<Answer, QuicError> {
    let unspecified = match server.ip() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let endpoint =
        quinn::Endpoint::client(SocketAddr::new(unspecified, 0)).map_err(QuicError::Io)?;
    // The name is the server's address, which the client doesn't check: it pins the key.
    let connection = endpoint
        .connect_with(client_config, server, &server.ip().to_string())?
        .await?;
    let answer = async {
        let (mut driver, mut send_request) =
            h3::client::new(h3_quinn::Connection::new(connection.clone())).await?;
        let request = async {
            let mut stream = send_request.send_request(request).await?;
            if let Some(body) = body {
                stream.send_data(Bytes::from(body)).await?;
            }
            stream.finish().await?;
            let response = stream.recv_response().await?;
            let content_type = response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);
            let mut body = vec![];
            while let Some(mut chunk) = stream.recv_data().await? {
                while chunk.has_remaining() && body.len() as u64 <= MAX_RESPONSE_LEN {
                    let bytes = chunk.chunk();
                    let take = bytes.len().min(MAX_RESPONSE_LEN as usize + 1 - body.len());
                    body.extend_from_slice(&bytes[..take]);
                    chunk.advance(take);
                }
                if body.len() as u64 > MAX_RESPONSE_LEN {
                    break;
                }
            }
            Ok::<_, QuicError>(Answer {
                status: response.status().as_u16(),
                content_type,
                body,
            })
        };
        tokio::select! {
            answer = request => answer,
            error = std::future::poll_fn(|cx| driver.poll_close(cx)) => {
                Err(QuicError::Http3(error.to_string()))
            },
        }
    }
    .await;
    connection.close(0u32.into(), b"");
    // Long enough for the close to leave, but not to drain the connection.
    let _ = tokio::time::timeout(Duration::from_millis(50), endpoint.wait_idle()).await;
    answer
}

/// An answer of the server over QUIC.
#[derive(Debug)]
struct Answer {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl Answer {
    /// The body of the answer, an answer of the TLS API, or the refusal that it is. The server
    /// explains every refusal in a problem detail, whose type alone says what the refusal means. A
    /// body must state the version of the API that the client reads, so that the client never
    /// reads a body of another version as one of its own.
    fn into_tls_body(self) -> Result<Vec<u8>, RestError> {
        let Answer {
            status,
            content_type,
            body,
        } = self;
        if status >= 400 {
            if content_type
                .as_deref()
                .is_some_and(problem::is_content_type)
            {
                return Err(match read_problem(&body) {
                    Some(problem) => RestError::from_problem(status, problem),
                    None => RestError::Status(status),
                });
            }
            // A refusal without a problem detail, which the server never makes, is explained as
            // one in plain HTTP is.
            let message = explanation(&body);
            return Err(if message.is_empty() {
                RestError::Status(status)
            } else {
                RestError::Refused { status, message }
            });
        }
        check_length(&body)?;
        let version = content_type
            .as_deref()
            .and_then(|header| media_type::body_version(header, &[media_type::VERSION]));
        if !body.is_empty() && version.is_none() {
            return Err(RestError::ResponseDeserialize(anyhow::anyhow!(
                "the response is of the content type {content_type:?}, not of version {} of the \
                 API",
                media_type::VERSION
            )));
        }
        Ok(body)
    }
}

/// At most `limit` bytes of `body`.
async fn read_limited(mut body: hyper::Body, limit: u64) -> io::Result<Vec<u8>> {
    use hyper::body::HttpBody as _;
    let mut bytes = vec![];
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(io::Error::other)?;
        let take = chunk
            .len()
            .min((limit as usize).saturating_sub(bytes.len()));
        bytes.extend_from_slice(&chunk[..take]);
        if bytes.len() as u64 >= limit {
            break;
        }
    }
    Ok(bytes)
}

/// Refuses a body longer than the client reads.
fn check_length(body: &[u8]) -> Result<(), RestError> {
    if body.len() as u64 > MAX_RESPONSE_LEN {
        return Err(RestError::ResponseRead(io::Error::new(
            io::ErrorKind::InvalidData,
            "the response is too long",
        )));
    }
    Ok(())
}

/// Whether the peers `a` and `b` are the same, but for what the server's tag of a peer leaves
/// out: their endpoints and candidates and their announcements, which a peer reports on its own,
/// and their delegations, which an admin changes apart from the rest of the peer.
fn same_but_untagged(a: &PeerContents, b: &PeerContents) -> bool {
    let tagged = |peer: &PeerContents| PeerContents {
        delegations: vec![],
        endpoint: None,
        candidates: vec![],
        announcement: None,
        allowed_ips: None,
        primary_ip: None,
        ..peer.clone()
    };
    tagged(a) == tagged(b)
}

/// The longest answer that the client reads.
const MAX_RESPONSE_LEN: u64 = 10 * 1024 * 1024;

/// Decodes the body of an answer in `transport`: as CBOR in its deterministic encoding over TLS,
/// and as JSON in plain HTTP. An empty body decodes as `null`, so that it decodes as `()`.
fn decode<T: DeserializeOwned>(transport: Transport, body: &[u8]) -> Result<T, RestError> {
    match transport {
        Transport::Tls => {
            let body = if body.is_empty() { &[0xf6][..] } else { body };
            cbor::from_slice(body).map_err(|e| RestError::ResponseDeserialize(e.into()))
        },
        Transport::Plain => {
            let body = if body.is_empty() { b"null" } else { body };
            serde_json::from_slice(body).map_err(|e| RestError::ResponseDeserialize(e.into()))
        },
    }
}

/// The ID by which a server in plain HTTP names the CIDR `prefix`, among `cidrs` as it lists them,
/// or [`RestError::NoSuchCidr`] if it lists no CIDR with the prefix.
fn legacy_cidr_id(cidrs: &[LegacyCidr], prefix: &Prefix) -> Result<i64, RestError> {
    cidrs
        .iter()
        .find(|cidr| cidr.prefix() == *prefix)
        .map(|cidr| cidr.id)
        .ok_or(RestError::NoSuchCidr)
}

/// The transport that a server answered a request in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// TLS, authenticated with the server's key.
    Tls,
    /// Plain HTTP, as servers that predate TLS speak it.
    Plain,
}

/// The admin API that a server offers a client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminApi {
    /// The API of TLS sessions, which addresses peers by public key only.
    ByKey,
    /// The API of plain-HTTP sessions with a server that predates TLS, which addresses peers by
    /// ID.
    Legacy,
}

/// How many bytes of the server's explanation of a refusal the client reads.
const MAX_EXPLANATION_LEN: u64 = 1024;

/// The server's explanation of a refusal, in `body`, escaped as [`escape`] escapes it.
fn explanation(body: &[u8]) -> String {
    let body = &body[..body.len().min(MAX_EXPLANATION_LEN as usize)];
    escape(&String::from_utf8_lossy(body))
}

/// How many bytes of a problem detail the client reads.
const MAX_PROBLEM_LEN: usize = 16 * 1024;

/// The problem detail in `body`, or `None` if it doesn't decode, or is too long. Its type, title
/// and detail are escaped as [`escape`] escapes them, since a problem is shown by its detail, or
/// else its title, or else its type. The URI of a type of innernet's own has nothing to escape, so
/// the problem's type still names it.
fn read_problem(body: &[u8]) -> Option<Problem> {
    if body.len() > MAX_PROBLEM_LEN {
        return None;
    }
    let mut problem: Problem = cbor::from_slice(body).ok()?;
    problem.problem_type = escape(&problem.problem_type);
    problem.title = problem.title.as_deref().map(escape);
    problem.detail = problem.detail.as_deref().map(escape);
    Some(problem)
}

/// At most [`MAX_EXPLANATION_LEN`] bytes of `text`, the server's, trimmed and escaped as
/// [`str::escape_debug`] escapes it, so that printing it can't affect the terminal.
fn escape(text: &str) -> String {
    let mut len = text.len().min(MAX_EXPLANATION_LEN as usize);
    while !text.is_char_boundary(len) {
        len -= 1;
    }
    text[..len].trim().escape_debug().to_string()
}

/// An error of a request over QUIC.
#[derive(Debug, Error)]
pub enum QuicError {
    /// The client failed to start the connection, such as for an address that it can't reach.
    #[error("{0}")]
    Connect(#[from] quinn::ConnectError),
    /// The connection failed, such as when nothing answered, or when the handshake failed, as
    /// when the server presents another key than the pinned one.
    #[error("{0}")]
    Connection(#[from] quinn::ConnectionError),
    /// HTTP/3 failed on the connection.
    #[error("HTTP/3 error: {0}")]
    Http3(String),
    /// The request could not be made.
    #[error("{0}")]
    Request(String),
    #[error("I/O error: {0}")]
    Io(io::Error),
}

impl From<h3::error::ConnectionError> for QuicError {
    fn from(error: h3::error::ConnectionError) -> Self {
        QuicError::Http3(error.to_string())
    }
}

impl From<h3::error::StreamError> for QuicError {
    fn from(error: h3::error::StreamError) -> Self {
        QuicError::Http3(error.to_string())
    }
}

impl QuicError {
    /// Whether the client failed to connect to the TLS API, before any request was made.
    pub fn is_connection_failure(&self) -> bool {
        matches!(self, QuicError::Connect(_) | QuicError::Connection(_))
    }

    /// Whether nothing answered: the server is down, unreachable, or doesn't listen at the port.
    pub fn is_unanswered(&self) -> bool {
        matches!(
            self,
            QuicError::Connection(quinn::ConnectionError::TimedOut)
                | QuicError::Connect(quinn::ConnectError::InvalidRemoteAddress(_))
        )
    }
}

#[derive(Debug, Error)]
pub enum RestError {
    #[error("Error setting up TLS: {0}")]
    TlsConfig(anyhow::Error),
    #[error(
        "The innernet server states no QUIC port, as servers that predate TLS do, but it is \
         known to speak TLS, so the client refuses to fall back to plain HTTP."
    )]
    ServerDowngraded,
    #[error("Error reading the data store: {0:#}")]
    DataStore(anyhow::Error),
    /// The MTU of the interface is too small for QUIC.
    #[error("{0}")]
    Mtu(anyhow::Error),
    #[error(
        "The peer has changed since it was listed, so the change was not made. Running the \
         command again lists the peers anew."
    )]
    PeerChanged,
    #[error(
        "No peer has this public key (the invitation may have been redeemed under a new key, or \
         have expired), so the change was not made. Running the command again lists the peers \
         anew."
    )]
    NoSuchPeer,
    #[error(
        "The innernet server predates TLS, and can't hold a peer without a name. The operator \
         must upgrade the server first."
    )]
    NamelessUnsupported,
    #[error(
        "The innernet server predates TLS, and offers a peer a single address only, not \
         delegations. The operator must upgrade the server first."
    )]
    DelegationsUnsupported,
    #[error(
        "The innernet server has no CIDR with this prefix (it may have been deleted), so the \
         change was not made. Running the command again lists the CIDRs anew."
    )]
    NoSuchCidr,
    #[error(
        "The CIDR has changed since it was listed, so the change was not made. Running the \
         command again lists the CIDRs anew."
    )]
    CidrChanged,
    #[error(
        "The innernet server has no association of these CIDRs (it may have been deleted), so \
         the change was not made. Running the command again lists the associations anew."
    )]
    NoSuchAssociation,
    /// A transport error in plain HTTP; error statuses are [`Self::Status`], [`Self::Refused`]
    /// and [`Self::Problem`].
    #[error("Error sending request: {0}")]
    RequestSend(Box<dyn std::error::Error + Send + Sync>),
    /// An error of a request over QUIC, to the TLS API.
    #[error("Error over QUIC: {0}")]
    Quic(#[from] QuicError),
    #[error("The server responded with status {0}")]
    Status(u16),
    #[error("The server refused the request ({status}): {message}")]
    Refused { status: u16, message: String },
    /// A refusal over TLS, with a problem detail of a type that has no error of its own.
    #[error("The server refused the request ({status}): {problem}")]
    Problem { status: u16, problem: Box<Problem> },
    #[error("Error serializing request: {0}")]
    RequestSerialize(anyhow::Error),
    #[error("Error deserializing response: {0}")]
    ResponseDeserialize(anyhow::Error),
    #[error("Error reading response: {0}")]
    ResponseRead(io::Error),
}

impl RestError {
    /// Whether the error is a refusal with the status `status` without a problem detail, as a
    /// server in plain HTTP refuses a request. A problem detail is decided on by its type alone.
    pub fn has_status_of(&self, status: u16) -> bool {
        match self {
            RestError::Status(s) | RestError::Refused { status: s, .. } => *s == status,
            _ => false,
        }
    }

    /// The error that the problem detail `problem`, of a refusal with the status `status`, says
    /// by its type: [`Self::PeerChanged`] and [`Self::CidrChanged`] for a stale tag,
    /// [`Self::NoSuchPeer`], [`Self::NoSuchCidr`] and [`Self::NoSuchAssociation`] for what the
    /// server doesn't hold, and [`Self::Problem`] for any other type.
    fn from_problem(status: u16, problem: Problem) -> Self {
        let errors = [
            (&problem::PEER_CHANGED, RestError::PeerChanged),
            (&problem::CIDR_CHANGED, RestError::CidrChanged),
            (&problem::NO_SUCH_PEER, RestError::NoSuchPeer),
            (&problem::NO_SUCH_CIDR, RestError::NoSuchCidr),
            (&problem::NO_SUCH_ASSOCIATION, RestError::NoSuchAssociation),
        ];
        errors
            .into_iter()
            .find(|(problem_type, _)| problem.is(problem_type))
            .map(|(_, error)| error)
            .unwrap_or(RestError::Problem {
                status,
                problem: Box::new(problem),
            })
    }

    /// Turns a refusal with 404, which a server in plain HTTP answers for a resource that it
    /// doesn't hold, into `error`, which says what was not found.
    fn not_found_as(self, error: Self) -> Self {
        if self.has_status_of(404) {
            error
        } else {
            self
        }
    }

    /// Whether the request failed to reach the server, as when the server is down or
    /// unreachable. A failed TLS handshake, such as one in which the server presents another key
    /// than the pinned one, is not: something answered at the server's address.
    pub fn is_transport_error(&self) -> bool {
        match self {
            RestError::RequestSend(_) => true,
            RestError::Quic(error) => error.is_unanswered(),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innernet_shared::{RedeemContents, Tag};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc, Arc, Mutex,
        },
        thread,
    };
    use wireguard_control::KeyPair;

    /// The config of a client of the server with the key `server`, whose legacy API is at
    /// `internal_endpoint`, without a QUIC port, as an invitation of v2.0.0 has none.
    fn config(internal_endpoint: SocketAddr, server: &KeyPair) -> InterfaceConfig {
        config_with_port(internal_endpoint, None, server)
    }

    /// The config of a client of the server with the key `server`, whose legacy API is at
    /// `internal_endpoint`, and whose TLS API is at `quic_port` of its address, if any.
    fn config_with_port(
        internal_endpoint: SocketAddr,
        quic_port: Option<u16>,
        server: &KeyPair,
    ) -> InterfaceConfig {
        let client = KeyPair::generate();
        let quic_port = quic_port
            .map(|port| format!("quic-port = {port}"))
            .unwrap_or_default();
        toml::from_str(&format!(
            r#"
            [interface]
            network-name = "test"
            address = "10.0.0.2/24"
            private-key = "{}"
            listen-port = 51820

            [server]
            public-key = "{}"
            external-endpoint = "203.0.113.1:51820"
            internal-endpoint = "{internal_endpoint}"
            {quic_port}
            "#,
            client.private.to_base64(),
            server.public.to_base64(),
        ))
        .unwrap()
    }

    /// The config of a client of the server with the key `server`, whose TLS API is at `addr`,
    /// as an invitation states it. Nothing serves the legacy API at the same port of TCP.
    fn quic_config(addr: SocketAddr, server: &KeyPair) -> InterfaceConfig {
        config_with_port(addr, Some(addr.port()), server)
    }

    /// The answer of a server that predates TLS to a request for the capabilities: none, so
    /// no QUIC port.
    const NO_CAPABILITIES: &str =
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\
         Connection: close\r\n\r\n{}";

    /// The answer of a server to a request for the capabilities in plain HTTP, which states that
    /// its TLS API is at QUIC port `port`.
    fn capabilities_response(port: u16) -> String {
        json_response(
            "200 OK",
            &format!(r#"{{"unspecified_ip_in_override_endpoint": true, "quic_port": {port}}}"#),
        )
    }

    /// Answers each connection in plain HTTP with `response`, like a server that predates TLS,
    /// and returns the request line of each request.
    fn plain_http_server_recording(
        connections: usize,
        response: &'static str,
    ) -> (SocketAddr, thread::JoinHandle<Vec<String>>) {
        plain_http_server_answering(vec![response.to_string(); connections])
    }

    /// Answers each connection in plain HTTP with the next of `responses`, like a server that
    /// predates TLS, and returns the request line of each request.
    fn plain_http_server_answering(
        responses: Vec<String>,
    ) -> (SocketAddr, thread::JoinHandle<Vec<String>>) {
        plain_http_server_at(TcpListener::bind("127.0.0.1:0").unwrap(), responses)
    }

    /// Answers each connection to `listener` in plain HTTP with the next of `responses`, and
    /// returns the request line of each request.
    fn plain_http_server_at(
        listener: TcpListener,
        responses: Vec<String>,
    ) -> (SocketAddr, thread::JoinHandle<Vec<String>>) {
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut requests = vec![];
            for (response, stream) in responses.into_iter().zip(listener.incoming()) {
                let mut stream = stream.unwrap();
                let mut buffer = [0u8; 4096];
                let read = stream.read(&mut buffer).unwrap();
                let request = String::from_utf8_lossy(&buffer[..read]);
                requests.push(request.lines().next().unwrap_or_default().to_string());
                stream.write_all(response.as_bytes()).unwrap();
            }
            requests
        });
        (addr, handle)
    }

    /// Answers each connection over QUIC, authenticated with `server`'s key, with an empty
    /// response.
    fn tls_server(server: &KeyPair, connections: usize) -> SocketAddr {
        tls_server_answering(
            server,
            connections,
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        )
    }

    /// Answers each connection over TLS, authenticated with `server`'s key, with `response`.
    fn tls_server_answering(
        server: &KeyPair,
        connections: usize,
        response: Vec<u8>,
    ) -> std::net::SocketAddr {
        tls_server_recording(server, vec![response; connections]).0
    }

    /// A request that a test server received: its head, which it reads as, and its body.
    struct Recorded {
        head: String,
        body: Vec<u8>,
    }

    impl std::ops::Deref for Recorded {
        type Target = str;

        fn deref(&self) -> &str {
            &self.head
        }
    }

    impl std::fmt::Display for Recorded {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.head)
        }
    }

    impl Recorded {
        /// The body, decoded from CBOR, which the head must state as its content type, in the
        /// newest version of the API.
        fn cbor<T: DeserializeOwned>(&self) -> T {
            assert_eq!(
                self.header("content-type").as_deref(),
                Some("application/vnd.innernet+cbor; version=1"),
                "{}",
                self.head
            );
            cbor::from_slice(&self.body).unwrap()
        }

        /// The value of the header `name` of the request, if it has one.
        fn header(&self, name: &str) -> Option<String> {
            self.head.lines().find_map(|line| {
                let (header, value) = line.split_once(':')?;
                header
                    .eq_ignore_ascii_case(name)
                    .then(|| value.trim().to_string())
            })
        }
    }

    /// Answers each connection over QUIC, in HTTP/3, authenticated with `server`'s key, with the
    /// next of `responses`, and sends each request, its head and its body, to the receiver. The
    /// head is that of HTTP/1.1, with the version `HTTP/3`; a response is written as one of
    /// HTTP/1.1, and sent without its connection-specific fields.
    fn tls_server_recording(
        server: &KeyPair,
        responses: Vec<Vec<u8>>,
    ) -> (SocketAddr, mpsc::Receiver<Recorded>) {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        tls_server_recording_at(socket, server, responses)
    }

    /// Answers each connection to `socket` as [`tls_server_recording`] does.
    fn tls_server_recording_at(
        socket: std::net::UdpSocket,
        server: &KeyPair,
        responses: Vec<Vec<u8>>,
    ) -> (SocketAddr, mpsc::Receiver<Recorded>) {
        let addr = socket.local_addr().unwrap();
        let config = tls::server_config(&server.private.to_base64()).unwrap();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(config).unwrap();
                let endpoint = quinn::Endpoint::new(
                    quinn::EndpointConfig::default(),
                    Some(quinn::ServerConfig::with_crypto(Arc::new(crypto))),
                    socket,
                    Arc::new(quinn::TokioRuntime),
                )
                .unwrap();
                for response in responses {
                    let Some(incoming) = endpoint.accept().await else {
                        break;
                    };
                    // A client that refuses the handshake ends the connection.
                    let Ok(connection) = incoming.await else {
                        continue;
                    };
                    let mut connection = h3::server::Connection::<_, Bytes>::new(
                        h3_quinn::Connection::new(connection),
                    )
                    .await
                    .unwrap();
                    let Ok(Some(resolver)) = connection.accept().await else {
                        continue;
                    };
                    let (request, mut stream) = resolver.resolve_request().await.unwrap();
                    let mut head = format!(
                        "{} {} HTTP/3\r\n",
                        request.method(),
                        request.uri().path_and_query().unwrap()
                    );
                    for (name, value) in request.headers() {
                        head += &format!("{name}: {}\r\n", value.to_str().unwrap());
                    }
                    head += "\r\n";
                    let mut body = vec![];
                    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
                        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                    }
                    let _ = sender.send(Recorded { head, body });

                    let (head, body) = split_response(&response);
                    stream.send_response(head).await.unwrap();
                    if !body.is_empty() {
                        stream.send_data(Bytes::from(body)).await.unwrap();
                    }
                    stream.finish().await.unwrap();
                    // The client closes the connection once it has read the response.
                    let _ = connection.accept().await;
                }
            });
        });
        (addr, receiver)
    }

    /// The head and the body of `response`, a response of HTTP/1.1, without the fields that
    /// HTTP/3 doesn't carry.
    fn split_response(response: &[u8]) -> (http::Response<()>, Vec<u8>) {
        let end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();
        let head = String::from_utf8(response[..end].to_vec()).unwrap();
        let mut lines = head.lines();
        let status: u16 = lines
            .next()
            .unwrap()
            .split(' ')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let mut builder = http::Response::builder().status(status);
        for line in lines {
            let (name, value) = line.split_once(':').unwrap();
            if !["connection", "content-length"].contains(&name.to_lowercase().as_str()) {
                builder = builder.header(name, value.trim());
            }
        }
        (builder.body(()).unwrap(), response[end + 4..].to_vec())
    }

    /// A response with the status `status` and the JSON body `body`.
    fn json_response(status: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        )
    }

    /// A response with the status `status` and the body `body`, in CBOR, in the newest version of
    /// the API.
    fn cbor_response(status: &str, body: &impl Serialize) -> Vec<u8> {
        cbor_response_as(status, "application/vnd.innernet+cbor; version=1", body)
    }

    /// A response with the status `status` and the body `body`, in CBOR, stated to be of the
    /// content type `content_type`.
    fn cbor_response_as(status: &str, content_type: &str, body: &impl Serialize) -> Vec<u8> {
        let body = cbor::to_vec(body).unwrap();
        let mut response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend(body);
        response
    }

    /// A refusal with the status `status` and the problem detail `problem`.
    fn problem_body_response(status: u16, problem: &Problem) -> Vec<u8> {
        let body = cbor::to_vec(problem).unwrap();
        let mut response = format!(
            "HTTP/1.1 {status} Refused\r\nContent-Type: application/problem+cbor\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend(body);
        response
    }

    /// A refusal with a problem of the type `problem_type`, with its status.
    fn problem_response(problem_type: &problem::ProblemType) -> Vec<u8> {
        problem_body_response(problem_type.status, &problem_type.problem("refused"))
    }

    #[tokio::test]
    async fn test_decides_on_the_type_of_problems() {
        // Over TLS, the type of a problem says what a refusal means, whatever its status. A
        // problem of another type, about:blank included, is reported as it is, and a refusal
        // without a problem by its status alone.
        let server_key = KeyPair::generate();
        let peer = listed_peer();
        let mut odd_status = problem::NO_SUCH_PEER.problem("gone");
        odd_status.status = Some(400);
        let blank = Problem::about_blank(404, Some("Not Found"));
        let unknown = Problem {
            problem_type: "urn:uuid:00000000-0000-4000-8000-000000000000".into(),
            ..problem::PEER_CHANGED.problem("later")
        };
        let (addr, _requests) = tls_server_recording(
            &server_key,
            vec![
                problem_body_response(400, &odd_status),
                problem_body_response(404, &blank),
                problem_body_response(409, &unknown),
                "HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\n\r\n".into(),
            ],
        );
        let config = quic_config(addr, &server_key);
        let client = RestClient::new(&config, true).unwrap();
        let error = client.get_tagged_peer(&peer).await.unwrap_err();
        assert!(matches!(error, RestError::NoSuchPeer), "{error:?}");
        match client.get_tagged_peer(&peer).await.unwrap_err() {
            RestError::Problem { status, problem } => {
                assert_eq!((status, *problem), (404, blank));
            },
            error => panic!("{error:?}"),
        }
        match client.get_tagged_peer(&peer).await.unwrap_err() {
            RestError::Problem { status, problem } => {
                assert_eq!((status, *problem), (409, unknown));
            },
            error => panic!("{error:?}"),
        }
        let error = client.get_tagged_peer(&peer).await.unwrap_err();
        assert!(matches!(error, RestError::Status(409)), "{error:?}");

        // The detail, the title and the type of a problem are escaped, which leaves the type of
        // a problem of innernet's own as it is.
        let refused = problem::DELEGATION_REFUSED.problem("\x1b[31mrefused\nfor now\x07");
        let problem = read_problem_of(&problem_response_of(&refused)).await;
        assert_eq!(
            problem.detail.as_deref(),
            Some(r"\u{1b}[31mrefused\nfor now\u{7}")
        );
        assert!(problem.is(&problem::DELEGATION_REFUSED));
        let mut untitled = Problem::about_blank(500, None);
        untitled.problem_type = "urn:\x1b[2J".to_string();
        let problem = read_problem_of(&problem_response_of(&untitled)).await;
        assert_eq!(problem.to_string(), r"urn:\u{1b}[2J");
    }

    /// A refusal with the problem `problem`, with its status.
    fn problem_response_of(problem: &Problem) -> Vec<u8> {
        problem_body_response(problem.status.unwrap(), problem)
    }

    /// The problem that the client reads of `response`, a refusal over TLS.
    async fn read_problem_of(response: &[u8]) -> Problem {
        let server_key = KeyPair::generate();
        let addr = tls_server_answering(&server_key, 1, response.to_vec());
        let config = quic_config(addr, &server_key);
        let client = RestClient::new(&config, true).unwrap();
        match client.http::<()>("GET", "/user/state").await.unwrap_err() {
            RestError::Problem { problem, .. } => *problem,
            error => panic!("{error:?}"),
        }
    }

    fn listed_peer() -> PeerContents {
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_mut(3) {
            chunk.copy_from_slice(&[0xfb, 0xff, 0xbf][..chunk.len()]);
        }
        PeerContents {
            name: Some("peer".parse().unwrap()),
            delegations: vec!["10.0.0.7/32".parse().unwrap()],
            public_key: wireguard_control::Key(bytes).to_base64(),
            endpoint: None,
            persistent_keepalive_interval: None,
            is_admin: false,
            is_disabled: false,
            is_redeemed: true,
            invite_expires: None,
            candidates: vec![],
            announcement: None,
            allowed_ips: None,
            primary_ip: None,
        }
    }

    const NO_CONTENT: &str = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";

    /// [`NO_CONTENT`], for a server that closes each connection after its answer.
    const NO_CONTENT_CLOSE: &str =
        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

    /// The tag whose bytes are those of `text`, as a test server makes up tags.
    fn test_tag(text: &str) -> Tag {
        Tag::new(text.as_bytes().to_vec())
    }

    /// The server's answer to a read of `peer` with the tag `tag`.
    fn tagged_response(peer: &PeerContents, tag: &str) -> Vec<u8> {
        let tagged = TaggedPeer {
            peer: peer.clone(),
            tag: test_tag(tag),
        };
        cbor_response("200 OK", &tagged)
    }

    /// The answer of a server in plain HTTP to a listing of `peers`, each with the ID 7.
    fn legacy_list_response(peers: &[PeerContents]) -> String {
        let peers: Vec<_> = peers
            .iter()
            .map(|contents| LegacyPeer {
                id: 7,
                contents: LegacyPeerContents::from_peer(contents, 1).unwrap(),
            })
            .collect();
        json_response("200 OK", &serde_json::to_string(&peers).unwrap())
    }

    #[tokio::test]
    async fn test_updates_peers_by_key_over_tls() {
        let server_key = KeyPair::generate();
        let peer = listed_peer();
        // The server reports the endpoint that it observes, which the tag leaves out.
        let observed = PeerContents {
            endpoint: Some("198.51.100.1:51820".parse().unwrap()),
            ..peer.clone()
        };
        let (addr, requests) = tls_server_recording(
            &server_key,
            vec![tagged_response(&observed, "ab"), NO_CONTENT.into()],
        );
        let config = quic_config(addr, &server_key);
        let client = RestClient::new(&config, false).unwrap();

        // A client that knows the QUIC port of the TLS API offers the admin API by key, without
        // asking.
        assert_eq!(client.admin_api().await.unwrap(), AdminApi::ByKey);
        let renamed = PeerContents {
            name: Some("renamed".parse().unwrap()),
            ..peer.clone()
        };
        client.update_peer(&peer, &renamed).await.unwrap();

        // The client reads the peer by key, and changes it with the tag it read.
        let segment = peer.api_path_segment();
        assert!(!segment.contains(['+', '/']));
        let get = requests.recv().unwrap();
        assert!(
            get.starts_with(&format!("GET /admin/peers/{segment} ")),
            "{get}"
        );
        let put = requests.recv().unwrap();
        assert!(
            put.starts_with(&format!("PUT /admin/peers/{segment} ")),
            "{put}"
        );
        let body: PeerUpdate = put.cbor();
        assert_eq!(body, PeerUpdate::new(test_tag("ab"), &renamed));
    }

    #[tokio::test]
    async fn test_refuses_peers_changed_since_listed() {
        let server_key = KeyPair::generate();
        let peer = listed_peer();
        let promoted = PeerContents {
            is_admin: true,
            ..peer.clone()
        };
        let not_found = problem_response(&problem::NO_SUCH_PEER);
        let conflict = problem_response(&problem::PEER_CHANGED);
        let (addr, requests) = tls_server_recording(
            &server_key,
            vec![
                // The peer changed between the listing and the read.
                tagged_response(&promoted, "ab"),
                // The peer changed between the read and the change.
                tagged_response(&peer, "ab"),
                conflict,
                // No peer has the key any more, as when an invitation is redeemed under a new
                // key, before the read.
                not_found.clone(),
                // No peer has the key any more, between the read and the change.
                tagged_response(&peer, "ab"),
                not_found,
            ],
        );
        let config = quic_config(addr, &server_key);
        let client = RestClient::new(&config, true).unwrap();
        for _ in 0..2 {
            let error = client.update_peer(&peer, &peer).await.unwrap_err();
            assert!(matches!(error, RestError::PeerChanged), "{error:?}");
        }
        for _ in 0..2 {
            let error = client.update_peer(&peer, &peer).await.unwrap_err();
            assert!(matches!(error, RestError::NoSuchPeer), "{error:?}");
        }
        let methods: Vec<_> = requests
            .iter()
            .map(|request| request.split(' ').next().unwrap().to_string())
            .collect();
        assert_eq!(methods, ["GET", "GET", "PUT", "GET", "GET", "PUT"]);
    }

    #[tokio::test]
    async fn test_updates_peers_by_id_in_plain_http() {
        // The server observes an endpoint for the peer, which it didn't when the peer was listed.
        let peer = listed_peer();
        let observed = PeerContents {
            endpoint: Some("198.51.100.1:51820".parse().unwrap()),
            ..peer.clone()
        };
        let server_key = KeyPair::generate();
        let (addr, server) = plain_http_server_answering(vec![
            NO_CAPABILITIES.into(),
            legacy_list_response(&[observed]),
            NO_CONTENT_CLOSE.into(),
        ]);
        let config = config(addr, &server_key);
        let client = RestClient::new(&config, false).unwrap();

        // The client asks the server for the QUIC port, and the server states none. The client
        // lists the peers again for the ID of the peer, and changes it by its ID.
        assert_eq!(client.admin_api().await.unwrap(), AdminApi::Legacy);
        client.update_peer(&peer, &peer).await.unwrap();
        assert_eq!(
            server.join().unwrap(),
            [
                "GET /v1/user/capabilities HTTP/1.1",
                "GET /v1/admin/peers HTTP/1.1",
                "PUT /v1/admin/peers/7 HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn test_refuses_peers_changed_since_listed_in_plain_http() {
        // A peer that has changed since it was listed, or that is gone, is refused, and nothing
        // is changed.
        let peer = listed_peer();
        let promoted = PeerContents {
            is_admin: true,
            ..peer.clone()
        };
        let server_key = KeyPair::generate();
        let (addr, server) = plain_http_server_answering(vec![
            NO_CAPABILITIES.into(),
            legacy_list_response(&[promoted]),
            legacy_list_response(&[]),
        ]);
        let config = config(addr, &server_key);
        let client = RestClient::new(&config, false).unwrap();
        for _ in 0..2 {
            let error = client.update_peer(&peer, &peer).await.unwrap_err();
            assert!(matches!(error, RestError::PeerChanged), "{error:?}");
        }
        assert_eq!(
            server.join().unwrap(),
            [
                "GET /v1/user/capabilities HTTP/1.1",
                "GET /v1/admin/peers HTTP/1.1",
                "GET /v1/admin/peers HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn test_decodes_by_transport() {
        // A server in plain HTTP sends peers with their IDs, which are left out, and is never
        // sent a peer that it can't hold.
        let peer = listed_peer();
        let state = format!(
            r#"{{"peers": {}, "cidrs": []}}"#,
            serde_json::to_string(&[LegacyPeer {
                id: 7,
                contents: LegacyPeerContents::from_peer(&peer, 1).unwrap(),
            }])
            .unwrap()
        );
        let server_key = KeyPair::generate();
        let (addr, server) = plain_http_server_answering(vec![
            NO_CAPABILITIES.into(),
            json_response("200 OK", &state),
            legacy_list_response(std::slice::from_ref(&peer)),
        ]);
        let config = config(addr, &server_key);
        let client = RestClient::new(&config, false).unwrap();
        assert_eq!(
            client.get_state().await.unwrap().peers,
            std::slice::from_ref(&peer)
        );
        assert_eq!(
            client.get_peers().await.unwrap(),
            std::slice::from_ref(&peer)
        );
        let nameless = PeerContents { name: None, ..peer };
        let error = client.create_peer(&nameless).await.unwrap_err();
        assert!(matches!(error, RestError::NamelessUnsupported), "{error:?}");
        for delegations in [vec![], vec!["10.0.0.8/31".parse().unwrap()]] {
            let delegated = PeerContents {
                delegations,
                ..listed_peer()
            };
            let error = client.create_peer(&delegated).await.unwrap_err();
            assert!(
                matches!(error, RestError::DelegationsUnsupported),
                "{error:?}"
            );
        }
        let error = client.update_peer(&nameless, &nameless).await.unwrap_err();
        assert!(matches!(error, RestError::NamelessUnsupported), "{error:?}");
        assert_eq!(
            server.join().unwrap(),
            [
                "GET /v1/user/capabilities HTTP/1.1",
                "GET /v1/user/state HTTP/1.1",
                "GET /v1/admin/peers HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn test_speaks_cbor_over_tls() {
        // Over TLS, the client sends and reads CBOR, in which a key is text in base64, as in JSON.
        let peer = listed_peer();
        let state = State {
            peers: vec![peer.clone()],
            cidrs: vec![users_cidr()],
            observed_endpoint: None,
            invalid_peer_keys: vec![],
        };
        let server_key = KeyPair::generate();
        let (addr, requests) = tls_server_recording(
            &server_key,
            vec![cbor_response("200 OK", &state), NO_CONTENT.into()],
        );
        let config = quic_config(addr, &server_key);
        let client = RestClient::new(&config, true).unwrap();
        let received = client.get_state().await.unwrap();
        assert_eq!((received.peers, received.cidrs), (state.peers, state.cidrs));
        let redeem = RedeemContents {
            public_key: peer.public_key.clone(),
        };
        client
            .http_form::<_, ()>("POST", "/user/redeem", &redeem)
            .await
            .unwrap();
        let get = requests.recv().unwrap();
        assert_eq!(get.header("content-type"), None, "{get}");
        let post = requests.recv().unwrap();
        assert_eq!(post.cbor::<RedeemContents>(), redeem);
        assert_eq!(post.body[..14], *b"\xa1jpublic_keyx\x2c");
        assert_eq!(post.body[14..], *peer.public_key.as_bytes());
    }

    #[tokio::test]
    async fn test_states_the_version_over_tls() {
        let peer = listed_peer();
        let state = State {
            peers: vec![peer.clone()],
            cidrs: vec![],
            observed_endpoint: None,
            invalid_peer_keys: vec![],
        };
        let server_key = KeyPair::generate();
        let (addr, requests) = tls_server_recording(
            &server_key,
            vec![
                cbor_response("200 OK", &state),
                NO_CONTENT.into(),
                NO_CONTENT.into(),
                cbor_response_as("200 OK", "application/cbor", &state),
                cbor_response_as("200 OK", "application/vnd.innernet+cbor; version=2", &state),
                cbor_response_as("200 OK", "application/vnd.innernet+cbor", &state),
            ],
        );
        let config = quic_config(addr, &server_key);
        let client = RestClient::new(&config, true).unwrap();

        // Every request accepts the newest version, and every body states it. A change without a
        // form carries neither a body nor a content type.
        client.get_state().await.unwrap();
        let association = Association {
            cidr_1: "10.0.1.0/24".parse().unwrap(),
            cidr_2: "10.0.2.0/24".parse().unwrap(),
        };
        client.delete_association(&association).await.unwrap();
        client
            .http_form::<_, ()>("PUT", "/user/candidates", Vec::<String>::new())
            .await
            .unwrap();
        let accept =
            Some("application/vnd.innernet+cbor; version=1, application/problem+cbor".to_string());
        let get = requests.recv().unwrap();
        assert_eq!(get.header("accept"), accept, "{get}");
        assert_eq!(get.header("content-type"), None, "{get}");
        let delete = requests.recv().unwrap();
        assert_eq!(delete.header("accept"), accept, "{delete}");
        assert_eq!(delete.header("content-type"), None, "{delete}");
        assert!(delete.body.is_empty(), "{delete}");
        let put = requests.recv().unwrap();
        assert_eq!(put.header("accept"), accept, "{put}");
        assert!(put.cbor::<Vec<String>>().is_empty());

        // An answer that doesn't state the version that the client reads is refused.
        for _ in 0..3 {
            let error = client.get_state().await.unwrap_err();
            assert!(
                matches!(error, RestError::ResponseDeserialize(_)),
                "{error:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_sets_delegations_by_key_over_tls() {
        let server_key = KeyPair::generate();
        let peer = listed_peer();
        let tagged = |delegations: &[Prefix]| {
            let body = TaggedPeerDelegations {
                delegations: delegations.to_vec(),
                reclaim: delegations.to_vec(),
                tag: test_tag("ab"),
            };
            cbor_response("200 OK", &body)
        };
        let wider: Vec<Prefix> = vec![
            "10.0.0.7/32".parse().unwrap(),
            "10.0.0.16/28".parse().unwrap(),
        ];
        let (addr, requests) = tls_server_recording(
            &server_key,
            vec![
                tagged(&peer.delegations),
                NO_CONTENT.into(),
                // The delegations changed between the listing and the read.
                tagged(&wider),
            ],
        );
        let config = quic_config(addr, &server_key);
        let client = RestClient::new(&config, true).unwrap();

        // The client reads the delegations with their tag, and replaces them with the tag, keeping
        // those that are marked to be reclaimed, and marking the one that it asks to.
        client
            .set_delegations(&peer, wider.clone(), Some(wider[1]))
            .await
            .unwrap();
        let path = format!("/admin/peers/{}/delegations", peer.api_path_segment());
        assert!(requests
            .recv()
            .unwrap()
            .starts_with(&format!("GET {path} ")));
        let put = requests.recv().unwrap();
        assert!(put.starts_with(&format!("PUT {path} ")), "{put}");
        let body: TaggedPeerDelegations = put.cbor();
        assert_eq!(
            body,
            TaggedPeerDelegations {
                delegations: wider.clone(),
                reclaim: wider.clone(),
                tag: test_tag("ab")
            }
        );

        let error = client
            .set_delegations(&peer, vec![], None)
            .await
            .unwrap_err();
        assert!(matches!(error, RestError::PeerChanged), "{error:?}");
    }

    #[tokio::test]
    async fn test_cidrs_and_associations_by_prefix_over_tls() {
        let server_key = KeyPair::generate();
        let users = users_cidr();
        let (addr, requests) = tls_server_recording(
            &server_key,
            vec![
                tagged_cidr_response(&users, "ab"),
                NO_CONTENT.into(),
                problem_response(&problem::NO_SUCH_CIDR),
                NO_CONTENT.into(),
                problem_response(&problem::NO_SUCH_ASSOCIATION),
            ],
        );
        let config = quic_config(addr, &server_key);
        let client = RestClient::new(&config, true).unwrap();
        let association = Association {
            cidr_1: users.cidr,
            cidr_2: "fd00::/64".parse().unwrap(),
        };

        // A CIDR is named by its prefix, and an association by the prefixes of its CIDRs, and
        // the type of the server's problem says which is gone. The client reads a CIDR with its
        // tag, and renames it with the tag it read.
        client.rename_cidr(&users, "people").await.unwrap();
        let get = requests.recv().unwrap();
        assert!(get.starts_with("GET /admin/cidrs/10.0.1.0_24 "), "{get}");
        let put = requests.recv().unwrap();
        assert!(put.starts_with("PUT /admin/cidrs/10.0.1.0_24 "), "{put}");
        let body: TaggedCidr = put.cbor();
        assert_eq!(
            body,
            TaggedCidr {
                cidr: Cidr {
                    name: "people".into(),
                    cidr: users.cidr
                },
                tag: test_tag("ab")
            }
        );
        let error = client.delete_cidr(&users).await.unwrap_err();
        assert!(matches!(error, RestError::NoSuchCidr), "{error:?}");
        assert!(requests
            .recv()
            .unwrap()
            .starts_with("GET /admin/cidrs/10.0.1.0_24 "));
        client.delete_association(&association).await.unwrap();
        assert!(requests
            .recv()
            .unwrap()
            .starts_with("DELETE /admin/associations/10.0.1.0_24/fd00::_64 "));
        let error = client.delete_association(&association).await.unwrap_err();
        assert!(matches!(error, RestError::NoSuchAssociation), "{error:?}");
    }

    /// The CIDR `users`, as a client lists it.
    fn users_cidr() -> Cidr {
        Cidr {
            name: "users".into(),
            cidr: "10.0.1.0/24".parse().unwrap(),
        }
    }

    /// The server's answer to a read of `cidr` with the tag `tag`.
    fn tagged_cidr_response(cidr: &Cidr, tag: &str) -> Vec<u8> {
        let tagged = TaggedCidr {
            cidr: cidr.clone(),
            tag: test_tag(tag),
        };
        cbor_response("200 OK", &tagged)
    }

    #[tokio::test]
    async fn test_deletes_cidrs_by_tag_over_tls() {
        let server_key = KeyPair::generate();
        let users = users_cidr();
        let (addr, requests) = tls_server_recording(
            &server_key,
            vec![tagged_cidr_response(&users, "ab"), NO_CONTENT.into()],
        );
        let config = quic_config(addr, &server_key);
        let client = RestClient::new(&config, true).unwrap();

        // The client reads the CIDR by prefix, and deletes it with the tag it read.
        client.delete_cidr(&users).await.unwrap();
        let get = requests.recv().unwrap();
        assert!(get.starts_with("GET /admin/cidrs/10.0.1.0_24 "), "{get}");
        let delete = requests.recv().unwrap();
        assert!(
            delete.starts_with("DELETE /admin/cidrs/10.0.1.0_24 "),
            "{delete}"
        );
        let body: CidrDeletion = delete.cbor();
        assert_eq!(
            body,
            CidrDeletion {
                tag: test_tag("ab")
            }
        );
    }

    #[tokio::test]
    async fn test_refuses_cidrs_changed_since_listed() {
        let server_key = KeyPair::generate();
        let users = users_cidr();
        let renamed = Cidr {
            name: "people".into(),
            ..users.clone()
        };
        let conflict = problem_response(&problem::CIDR_CHANGED);
        let bad_request =
            problem_body_response(400, &Problem::about_blank(400, Some("Bad Request")));
        let (addr, requests) = tls_server_recording(
            &server_key,
            vec![
                // The CIDR changed between the listing and the read.
                tagged_cidr_response(&renamed, "ab"),
                tagged_cidr_response(&renamed, "ab"),
                // The CIDR changed between the read and the change.
                tagged_cidr_response(&users, "ab"),
                conflict.clone(),
                tagged_cidr_response(&users, "ab"),
                conflict,
                // The server refuses a change that it can't read, as one without a tag.
                tagged_cidr_response(&users, "ab"),
                bad_request,
            ],
        );
        let config = quic_config(addr, &server_key);
        let client = RestClient::new(&config, true).unwrap();
        let error = client.rename_cidr(&users, "people").await.unwrap_err();
        assert!(matches!(error, RestError::CidrChanged), "{error:?}");
        let error = client.delete_cidr(&users).await.unwrap_err();
        assert!(matches!(error, RestError::CidrChanged), "{error:?}");
        let error = client.rename_cidr(&users, "people").await.unwrap_err();
        assert!(matches!(error, RestError::CidrChanged), "{error:?}");
        let error = client.delete_cidr(&users).await.unwrap_err();
        assert!(matches!(error, RestError::CidrChanged), "{error:?}");
        let error = client.rename_cidr(&users, "people").await.unwrap_err();
        assert!(
            matches!(
                &error,
                RestError::Problem { status: 400, problem }
                    if problem.problem_type == "about:blank"
            ),
            "{error:?}"
        );
        let methods: Vec<_> = requests
            .iter()
            .map(|request| request.split(' ').next().unwrap().to_string())
            .collect();
        assert_eq!(
            methods,
            ["GET", "GET", "GET", "PUT", "GET", "DELETE", "GET", "PUT"]
        );
    }

    #[tokio::test]
    async fn test_cidrs_and_associations_by_id_in_plain_http() {
        // A server in plain HTTP names CIDRs and associations by ID, so the client lists them
        // for the IDs, and leaves the IDs out of what it returns.
        let cidrs = r#"[
            {"id": 1, "name": "root", "cidr": "10.0.0.0/16", "parent": null},
            {"id": 3, "name": "users", "cidr": "10.0.1.0/24", "parent": 1}
        ]"#;
        let created = r#"{"id": 4, "name": "new", "cidr": "10.0.1.128/25", "parent": 3}"#;
        let associations = r#"[{"id": 5, "cidr_id_1": 3, "cidr_id_2": 1}]"#;
        let server_key = KeyPair::generate();
        let (addr, server) = plain_http_server_answering(vec![
            NO_CAPABILITIES.into(),
            json_response("200 OK", cidrs),
            json_response("201 Created", created),
            json_response("200 OK", cidrs),
            NO_CONTENT_CLOSE.into(),
            json_response("200 OK", associations),
            json_response("200 OK", cidrs),
            json_response("200 OK", cidrs),
            json_response("200 OK", associations),
            NO_CONTENT_CLOSE.into(),
            json_response("200 OK", cidrs),
            NO_CONTENT_CLOSE.into(),
        ]);
        let config = config(addr, &server_key);
        let client = RestClient::new(&config, false).unwrap();
        let prefix = |prefix: &str| prefix.parse::<Prefix>().unwrap();
        let new = Cidr {
            name: "new".into(),
            cidr: prefix("10.0.1.128/25"),
        };
        assert_eq!(client.admin_api().await.unwrap(), AdminApi::Legacy);
        assert_eq!(client.create_cidr(&new).await.unwrap(), new);
        let association = Association {
            cidr_1: prefix("10.0.0.0/16"),
            cidr_2: prefix("10.0.1.0/24"),
        };
        client.create_association(&association).await.unwrap();
        assert_eq!(
            client.get_associations().await.unwrap(),
            [Association {
                cidr_1: association.cidr_2,
                cidr_2: association.cidr_1,
            }]
        );
        client.delete_association(&association).await.unwrap();
        client.delete_cidr(&users_cidr()).await.unwrap();
        assert_eq!(
            server.join().unwrap(),
            [
                "GET /v1/user/capabilities HTTP/1.1",
                "GET /v1/admin/cidrs HTTP/1.1",
                "POST /v1/admin/cidrs HTTP/1.1",
                "GET /v1/admin/cidrs HTTP/1.1",
                "POST /v1/admin/associations HTTP/1.1",
                "GET /v1/admin/associations HTTP/1.1",
                "GET /v1/admin/cidrs HTTP/1.1",
                "GET /v1/admin/cidrs HTTP/1.1",
                "GET /v1/admin/associations HTTP/1.1",
                "DELETE /v1/admin/associations/5 HTTP/1.1",
                "GET /v1/admin/cidrs HTTP/1.1",
                "DELETE /v1/admin/cidrs/3 HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn test_no_delegations_in_plain_http() {
        // A server that predates TLS has no delegations, so nothing is sent to it.
        let server_key = KeyPair::generate();
        let (addr, server) = plain_http_server_recording(1, NO_CAPABILITIES);
        let config = config(addr, &server_key);
        let client = RestClient::new(&config, false).unwrap();
        let error = client
            .set_delegations(&listed_peer(), vec![], None)
            .await
            .unwrap_err();
        assert!(
            matches!(error, RestError::DelegationsUnsupported),
            "{error:?}"
        );
        assert_eq!(
            server.join().unwrap(),
            ["GET /v1/user/capabilities HTTP/1.1"]
        );
    }

    const BAD_REQUEST: &str =
        "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

    #[tokio::test]
    async fn test_falls_back_for_servers_that_predate_tls() {
        // A server that predates TLS states no QUIC port, or predates the capabilities too.
        for capabilities in [
            NO_CAPABILITIES,
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ] {
            let server_key = KeyPair::generate();
            let (addr, server) = plain_http_server_answering(vec![
                capabilities.into(),
                BAD_REQUEST.into(),
                BAD_REQUEST.into(),
            ]);
            let config = config(addr, &server_key);
            let client = RestClient::new(&config, false).unwrap();

            // The client asks for the port once, and makes its requests in plain HTTP.
            for _ in 0..2 {
                let error = client
                    .http::<String>("GET", "/user/state")
                    .await
                    .unwrap_err();
                assert!(error.has_status_of(400), "{error:?}");
            }
            assert!(!client.speaks_tls());
            assert_eq!(
                server.join().unwrap(),
                [
                    "GET /v1/user/capabilities HTTP/1.1",
                    "GET /v1/user/state HTTP/1.1",
                    "GET /v1/user/state HTTP/1.1",
                ]
            );
        }
    }

    #[tokio::test]
    async fn test_refuses_plain_http_from_servers_known_to_speak_tls() {
        let server_key = KeyPair::generate();
        let (addr, server) = plain_http_server_recording(2, NO_CAPABILITIES);
        let config = config(addr, &server_key);
        let client = RestClient::new(&config, true).unwrap();

        // Every request is refused, and none is sent in plain HTTP: the client only asks for the
        // QUIC port.
        for _ in 0..2 {
            let error = client
                .http::<String>("GET", "/user/state")
                .await
                .unwrap_err();
            assert!(matches!(error, RestError::ServerDowngraded), "{error:?}");
            assert!(!error.is_transport_error());
        }
        assert_eq!(
            server.join().unwrap(),
            [
                "GET /v1/user/capabilities HTTP/1.1",
                "GET /v1/user/capabilities HTTP/1.1"
            ]
        );
    }

    /// A UDP port of the loopback address at which nothing listens, at least for a while.
    fn unused_udp_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// A client of `config`, which records the QUIC ports that it learns in `ports`, and waits
    /// for the server for a short while only.
    fn recording_client<'a>(
        config: &'a InterfaceConfig,
        speaks_tls: bool,
        ports: &Arc<Mutex<Vec<u16>>>,
    ) -> RestClient<'a> {
        let ports = ports.clone();
        RestClient {
            record_port: Some(Box::new(move |port| {
                ports.lock().unwrap().push(port);
                Ok(())
            })),
            timeout: Duration::from_millis(500),
            ..RestClient::new(config, speaks_tls).unwrap()
        }
    }

    #[tokio::test]
    async fn test_learns_the_quic_port_from_the_server() {
        // A client upgraded from v2.0.0 has no QUIC port, and asks the server for it in plain
        // HTTP, as the server answers even a client that it requires to connect over TLS.
        let server_key = KeyPair::generate();
        let (quic, requests) = tls_server_recording(&server_key, vec![NO_CONTENT.into(); 2]);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (addr, server) =
            plain_http_server_at(listener, vec![capabilities_response(quic.port())]);
        let config = config(addr, &server_key);
        let ports = Arc::new(Mutex::new(vec![]));
        let client = recording_client(&config, true, &ports);
        for _ in 0..2 {
            client.http::<()>("GET", "/user/state").await.unwrap();
        }
        assert_eq!(client.quic_port(), Some(quic.port()));
        assert_eq!(*ports.lock().unwrap(), [quic.port()]);
        assert_eq!(
            server.join().unwrap(),
            ["GET /v1/user/capabilities HTTP/1.1"]
        );
        for request in requests.iter() {
            assert!(request.starts_with("GET /user/state "), "{request}");
        }
    }

    #[tokio::test]
    async fn test_reaches_a_server_at_an_ipv6_address() -> Result<(), anyhow::Error> {
        // A server whose internal address is IPv6 is reached in plain HTTP and over QUIC at that
        // address, which URLs hold in brackets, from a socket of the same family.
        let server_key = KeyPair::generate();
        let socket = std::net::UdpSocket::bind("[::1]:0")?;
        let (quic, requests) =
            tls_server_recording_at(socket, &server_key, vec![NO_CONTENT.into()]);
        let listener = TcpListener::bind("[::1]:0")?;
        let (addr, server) =
            plain_http_server_at(listener, vec![capabilities_response(quic.port())]);
        let config = config(addr, &server_key);
        let ports = Arc::new(Mutex::new(vec![]));
        let client = recording_client(&config, true, &ports);
        assert_eq!(client.address(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        client.http::<()>("GET", "/user/state").await?;
        assert_eq!(client.quic_port(), Some(quic.port()));
        let server = server
            .join()
            .map_err(|_| anyhow::anyhow!("the plain-HTTP server panicked"))?;
        assert_eq!(server, ["GET /v1/user/capabilities HTTP/1.1"]);
        let request = requests.recv()?;
        assert!(request.starts_with("GET /user/state "), "{request}");
        Ok(())
    }

    #[tokio::test]
    async fn test_asks_for_the_quic_port_again_when_quic_fails() {
        // Nothing answers at the port that the client knows, since the operator moved it.
        let server_key = KeyPair::generate();
        let (quic, _requests) = tls_server_recording(&server_key, vec![NO_CONTENT.into()]);
        let (addr, server) = plain_http_server_answering(vec![capabilities_response(quic.port())]);
        let config = config_with_port(addr, Some(unused_udp_port()), &server_key);
        let ports = Arc::new(Mutex::new(vec![]));
        let client = recording_client(&config, true, &ports);
        client.http::<()>("GET", "/user/state").await.unwrap();
        assert_eq!(*ports.lock().unwrap(), [quic.port()]);
        assert_eq!(
            server.join().unwrap(),
            ["GET /v1/user/capabilities HTTP/1.1"]
        );

        // A server downgraded to one that predates TLS states no port, and is refused.
        let (addr, server) = plain_http_server_recording(1, NO_CAPABILITIES);
        let config = config_with_port(addr, Some(unused_udp_port()), &server_key);
        let client = recording_client(&config, true, &ports);
        let error = client.http::<()>("GET", "/user/state").await.unwrap_err();
        assert!(matches!(error, RestError::ServerDowngraded), "{error:?}");
        assert_eq!(
            server.join().unwrap(),
            ["GET /v1/user/capabilities HTTP/1.1"]
        );

        // When the server states the same port, the client gives up, as when the server is down.
        let (addr, server) = plain_http_server_answering(vec![]);
        drop(server);
        let config = config_with_port(addr, Some(unused_udp_port()), &server_key);
        let client = recording_client(&config, true, &ports);
        let error = client.http::<()>("GET", "/user/state").await.unwrap_err();
        assert!(error.is_transport_error(), "{error:?}");
    }

    #[tokio::test]
    async fn test_latches_when_answered_over_tls() {
        let server_key = KeyPair::generate();
        let addr = tls_server(&server_key, 2);
        let config = quic_config(addr, &server_key);
        let latched = Arc::new(AtomicUsize::new(0));
        let client = RestClient {
            latch: Some(Box::new({
                let latched = latched.clone();
                move |()| {
                    latched.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            })),
            ..RestClient::new(&config, false).unwrap()
        };

        // The server is recorded as speaking TLS once, on its first answer.
        for _ in 0..2 {
            client.http::<()>("GET", "/user/state").await.unwrap();
        }
        assert!(client.speaks_tls());
        assert_eq!(latched.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_wrong_server_key_is_not_a_transport_error() {
        // A server that authenticates with another key than the pinned one isn't merely
        // unreachable.
        let addr = tls_server(&KeyPair::generate(), 1);
        let config = quic_config(addr, &KeyPair::generate());
        let client = RestClient::new(&config, false).unwrap();
        let error = client.http::<()>("GET", "/user/state").await.unwrap_err();
        assert!(!error.is_transport_error(), "{error:?}");
        assert!(!client.speaks_tls());
    }

    #[tokio::test]
    async fn test_explanations_are_sanitized() {
        // The server's explanation of a refusal is cut short, and its control characters are
        // escaped.
        let server_key = KeyPair::generate();
        let text = "\x1b[31mrefused\nby the server\x07";
        let body = format!("{text}{}", "x".repeat(10_000));
        let response = format!(
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let addr = tls_server_answering(&server_key, 1, response.into());
        let config = quic_config(addr, &server_key);
        let client = RestClient::new(&config, false).unwrap();
        match client.http::<()>("GET", "/user/state").await.unwrap_err() {
            RestError::Refused { status, message } => {
                assert_eq!(status, 401);
                let shown = "x".repeat(MAX_EXPLANATION_LEN as usize - text.len());
                assert_eq!(
                    message,
                    format!(r"\u{{1b}}[31mrefused\nby the server\u{{7}}{shown}")
                );
            },
            error => panic!("{error:?}"),
        }
    }

    #[tokio::test]
    async fn test_transport_errors() {
        // Nothing is listening, neither in plain HTTP nor over QUIC.
        let addr = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        for quic_port in [None, Some(unused_udp_port())] {
            let config = config_with_port(addr, quic_port, &KeyPair::generate());
            let client = RestClient {
                timeout: Duration::from_millis(500),
                ..RestClient::new(&config, false).unwrap()
            };
            let error = client
                .http::<String>("GET", "/user/state")
                .await
                .unwrap_err();
            assert!(error.is_transport_error(), "{error:?}");
        }
    }
}
