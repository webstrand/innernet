//! The DNS server, which answers for the names of the peers.
//!
//! Every node runs the same DNS server, a client and the server alike, from the names of its
//! snapshot, as [`crate::realize::DnsServer`] publishes them.
//!
//! The DNS server is authoritative for the zone of the names of the peers, the host suffix or
//! `<interface>.wg`. It answers a query for the hostname of an enabled peer, as this node names
//! it, itself, with the address at which the name of the peer resolves, its primary IP, except
//! for a peer to whose nameserver it forwards. Any other name of the zone, that of a disabled peer
//! included, doesn't exist.
//!
//! A peer that offers a nameserver announces it together with the zone that the nameserver
//! answers for. The DNS server forwards to the nameservers of the enabled peers that the
//! `forward` key of its config selects, and to none by default. It answers queries for the
//! hostname of such a peer and for the names under it by replacing the hostname with the zone,
//! forwarding the query to the peer's nameserver, and replacing the zone with the hostname again
//! in the response. It drops every record of a response whose owner isn't under the hostname, so
//! that a peer's nameserver only ever speaks for the peer's own names, and every address record
//! whose address lies outside the delegation that the peer claims, so that it only ever points at
//! the peer's own addresses.
//!
//! A name under the hostnames of several peers is the longest one's. The DNS server refuses
//! queries for names outside the zone.
//!
//! The DNS server answers over UDP and TCP at the same address. It runs at most
//! [`MAX_IN_FLIGHT`] queries at a time and refuses the rest, and gives each exchange with a
//! nameserver [`UPSTREAM_DEADLINE`] in all and each TCP connection of a client
//! [`CLIENT_DEADLINE`] in all, however slowly either side sends.

use crate::snapshot::Snapshot;
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{Name, RData, Record, RecordType},
};
use innernet_shared::{
    interface_config::Forwarding, peer_hostname, peer_zone, PeerContents, Prefix,
};
#[cfg(target_os = "linux")]
use std::fs;
use std::{
    collections::BTreeMap,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, PoisonError, RwLock,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
    time::Instant,
};
use wireguard_control::InterfaceName;

/// How long an exchange with a peer's nameserver may take in all.
pub const UPSTREAM_DEADLINE: Duration = Duration::from_secs(5);

/// How long a client's TCP connection may stay open in all.
pub const CLIENT_DEADLINE: Duration = Duration::from_secs(30);

/// The most queries that the DNS server answers at a time, over UDP and TCP together.
pub const MAX_IN_FLIGHT: usize = 64;

/// The largest DNS message, over TCP or UDP.
const MAX_MESSAGE_SIZE: usize = 65535;

/// The time to live of the address that the DNS server answers for the hostname of a peer.
const HOST_TTL: u32 = 60;

/// The lowest port that a user without privileges may bind, where the system doesn't say.
const UNPRIVILEGED_PORT_START: u16 = 1024;

/// What the DNS server answers for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Names {
    /// The zone of the names of the peers, for which the DNS server is authoritative.
    pub zone: Name,
    /// The address of the hostname of each peer that has a name.
    pub hosts: BTreeMap<Name, IpAddr>,
    /// Where queries go for the hostname of each peer to whose nameserver the DNS server
    /// forwards. A forward takes precedence over a host of the same hostname.
    pub forwards: Vec<Forward>,
}

impl Names {
    /// The names that `snapshot` publishes for `interface`, with the hostnames of the peers under
    /// `host_suffix`: the hosts of its names, and the forwards of its peers that offer a
    /// nameserver and that `forwarding` selects.
    pub fn of(
        interface: &InterfaceName,
        host_suffix: Option<&str>,
        forwarding: &Forwarding,
        snapshot: &Snapshot,
    ) -> Self {
        Self {
            zone: fqdn(&peer_zone(interface, host_suffix)).unwrap_or_default(),
            hosts: hosts(interface, host_suffix, &snapshot.names),
            forwards: forwards(interface, host_suffix, forwarding, &snapshot.peers),
        }
    }
}

/// The hostnames of `names`, the names that the node publishes, each with its address, under
/// `host_suffix`, as [`peer_hostname`] makes them. A peer whose name gives no hostname is left
/// out.
pub fn hosts(
    interface: &InterfaceName,
    host_suffix: Option<&str>,
    names: &BTreeMap<String, IpAddr>,
) -> BTreeMap<Name, IpAddr> {
    names
        .iter()
        .filter_map(|(name, ip)| {
            let hostname = peer_hostname(interface, host_suffix, name).and_then(|h| fqdn(&h));
            if hostname.is_none() {
                log::debug!(
                    "not answering for the peer named {}, whose name gives no hostname.",
                    name.escape_debug()
                );
            }
            Some((hostname?, *ip))
        })
        .collect()
}

/// The hostname of a peer to whose nameserver the DNS server forwards, and where queries for it
/// go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forward {
    /// The peer's hostname, as [`peer_hostname`] makes it.
    pub hostname: Name,
    /// The zone that the nameserver answers for in place of `hostname`.
    pub zone: Name,
    pub nameserver: SocketAddr,
    /// The delegation that the peer claims, within which every address that its nameserver
    /// answers must lie.
    pub delegation: Vec<Prefix>,
}

/// The forwards for the enabled peers of `peers`, as they take effect, that have a name and a
/// nameserver and that `forwarding` selects, with their hostnames under `host_suffix`, as
/// [`peer_hostname`] makes them. A name of `forwarding` that names no peer of `peers` is logged.
///
/// A hostname of a single label is skipped with a warning, since forwarding it would hand the
/// peer a whole top-level domain.
pub fn forwards(
    interface: &InterfaceName,
    host_suffix: Option<&str>,
    forwarding: &Forwarding,
    peers: &[PeerContents],
) -> Vec<Forward> {
    for name in forwarding.named() {
        if !peers.iter().any(|peer| peer.name.as_ref() == Some(name)) {
            log::debug!("forwarding names {name}, which names no peer.");
        }
    }
    peers
        .iter()
        .filter(|peer| !peer.is_disabled)
        .filter_map(|peer| {
            let nameserver = peer.nameserver.as_ref()?;
            let name = peer.name.as_ref()?;
            if !forwarding.selects(name) {
                return None;
            }
            let hostname = fqdn(&peer_hostname(interface, host_suffix, name)?)?;
            if hostname.num_labels() < 2 {
                log::warn!(
                    "not forwarding DNS for {hostname}, a single label, which would be a \
                     top-level domain; a host suffix that isn't empty names it under a domain."
                );
                return None;
            }
            Some(Forward {
                hostname,
                zone: fqdn(&nameserver.zone)?,
                nameserver: nameserver.address,
                delegation: peer.delegations.clone(),
            })
        })
        .collect()
}

fn fqdn(name: &str) -> Option<Name> {
    let mut name = Name::from_ascii(name).ok()?;
    name.set_fqdn(true);
    Some(name)
}

/// `name` with its suffix `from` replaced by `to`, or `None` if `name` is not `from` or a name
/// under it.
fn replace_suffix(name: &Name, from: &Name, to: &Name) -> Option<Name> {
    if !from.zone_of(name) {
        return None;
    }
    let keep = name.iter().count() - from.iter().count();
    let mut replaced = Name::from_labels(name.iter().take(keep))
        .ok()?
        .append_name(to)
        .ok()?;
    replaced.set_fqdn(true);
    Some(replaced)
}

/// The forward of `forwards` for `name`: the one whose hostname is the longest suffix of `name`,
/// so that a peer named under another peer's name answers for its own names.
fn route<'a>(forwards: &'a [Forward], name: &Name) -> Option<&'a Forward> {
    forwards
        .iter()
        .filter(|forward| forward.hostname.zone_of(name))
        .max_by_key(|forward| forward.hostname.num_labels())
}

/// A query as forwarded to a nameserver, with what is needed to restore the response.
#[derive(Debug)]
struct Forwarded {
    /// The query, with the hostname replaced by the zone.
    query: Vec<u8>,
    /// The name queried by the client, as the client spelled it.
    name: Name,
    /// The name as forwarded.
    forwarded_name: Name,
    /// The largest response that the client accepts over UDP.
    max_udp_size: usize,
    forward: Forward,
}

/// Prepares `query` for forwarding, or returns the response to send back instead: the address of
/// the hostname of a peer that isn't forwarded to, as [`host_response`] answers it, the answer
/// for a name that neither a host nor a forward of `names` holds, as [`not_found`] makes it, or a
/// refusal of a query that isn't a standard query of one question.
fn forward_query(names: &Names, query: &[u8]) -> Result<Forwarded, Vec<u8>> {
    let Ok(mut message) = Message::from_vec(query) else {
        return Err(error_response(query, ResponseCode::FormErr));
    };
    if message.metadata.message_type != MessageType::Query {
        return Err(vec![]);
    }
    if message.metadata.op_code != OpCode::Query {
        return Err(error_response(query, ResponseCode::NotImp));
    }
    if message.queries.len() != 1 {
        return Err(error_response(query, ResponseCode::Refused));
    }
    let name = message.queries[0].name().clone();
    let forward = route(&names.forwards, &name);
    let host = names
        .hosts
        .iter()
        .filter(|(host, _)| host.zone_of(&name))
        .max_by_key(|(host, _)| host.num_labels());
    if let Some((host, ip)) = host {
        if forward.is_none_or(|forward| forward.hostname.num_labels() < host.num_labels()) {
            return Err(host_response(&message, query, host, *ip));
        }
    }
    let Some(forward) = forward else {
        return Err(not_found(names, &message, query));
    };
    let Some(forwarded_name) = replace_suffix(&name, &forward.hostname, &forward.zone) else {
        return Err(error_response(query, ResponseCode::Refused));
    };
    message.queries[0].set_name(forwarded_name.clone());
    match message.to_vec() {
        Ok(query) => Ok(Forwarded {
            query,
            name,
            forwarded_name,
            max_udp_size: usize::from(message.max_payload()),
            forward: forward.clone(),
        }),
        Err(_) => Err(error_response(query, ResponseCode::ServFail)),
    }
}

/// The response to `message`, the standard query `query` of one question, for a name at or under
/// `host`, the hostname of a peer whose address is `ip`: for `host` itself, the address if the
/// query asks for one of its family, or for any type, and no record otherwise; a name under it
/// doesn't exist, since no nameserver answers for it. The response is authoritative, and small
/// enough for any client over UDP.
fn host_response(message: &Message, query: &[u8], host: &Name, ip: IpAddr) -> Vec<u8> {
    let question = &message.queries[0];
    if question.name() != host {
        return authoritative(message, query, ResponseCode::NXDomain);
    }
    let mut response = authoritative_response(message);
    let data = match (question.query_type(), ip) {
        (RecordType::A | RecordType::ANY, IpAddr::V4(ip)) => Some(RData::A(ip.into())),
        (RecordType::AAAA | RecordType::ANY, IpAddr::V6(ip)) => Some(RData::AAAA(ip.into())),
        _ => None,
    };
    if let Some(data) = data {
        response.add_answer(Record::from_rdata(question.name().clone(), HOST_TTL, data));
    }
    response
        .to_vec()
        .unwrap_or_else(|_| error_response(query, ResponseCode::ServFail))
}

/// Restores the names of a nameserver's `response` to what the client asked about: the queried
/// name as the client spelled it, and the zone replaced by the hostname in every other name within
/// it, whether it owns a record or appears in its data.
///
/// A record whose owner isn't under the hostname once restored is dropped, as is an A or AAAA
/// record whose address lies outside the delegation that the peer claims, and a record of a
/// type that may hold names that the DNS server doesn't restore, such as a DNSSEC record, whose
/// signature the restored names would break anyway, or a record of a type that it doesn't know.
/// A name in the data of a record that lies outside the zone, such as the target of an alias
/// elsewhere, is left as it is.
fn restore_response(forwarded: &Forwarded, response: &[u8]) -> Option<Message> {
    let mut message = Message::from_vec(response).ok()?;
    let Forward {
        hostname,
        zone,
        delegation,
        ..
    } = &forwarded.forward;
    let delegated = |ip: IpAddr| delegation.iter().any(|prefix| prefix.contains_addr(&ip));
    let restore = |name: &mut Name| {
        if *name == forwarded.forwarded_name {
            *name = forwarded.name.clone();
        } else if let Some(restored) = replace_suffix(name, zone, hostname) {
            *name = restored;
        }
    };
    for query in &mut message.queries {
        let mut name = query.name().clone();
        restore(&mut name);
        query.set_name(name);
    }
    let restore_record = |record: &mut Record| -> bool {
        restore(&mut record.name);
        if !hostname.zone_of(&record.name) {
            return false;
        }
        match &mut record.data {
            RData::CNAME(data) => restore(&mut data.0),
            RData::NS(data) => restore(&mut data.0),
            RData::PTR(data) => restore(&mut data.0),
            RData::ANAME(data) => restore(&mut data.0),
            RData::MX(data) => restore(&mut data.exchange),
            RData::SRV(data) => restore(&mut data.target),
            RData::NAPTR(data) => restore(&mut data.replacement),
            RData::SVCB(data) => restore(&mut data.target_name),
            RData::HTTPS(data) => restore(&mut data.0.target_name),
            RData::SOA(data) => {
                restore(&mut data.mname);
                restore(&mut data.rname);
            },
            RData::A(data) => return delegated(IpAddr::V4(data.0)),
            RData::AAAA(data) => return delegated(IpAddr::V6(data.0)),
            // Types whose data holds no names.
            RData::CAA(_)
            | RData::CERT(_)
            | RData::CSYNC(_)
            | RData::HINFO(_)
            | RData::OPENPGPKEY(_)
            | RData::SMIMEA(_)
            | RData::SSHFP(_)
            | RData::TLSA(_)
            | RData::TXT(_) => {},
            _ => return false,
        }
        true
    };
    for section in [
        &mut message.answers,
        &mut message.authorities,
        &mut message.additionals,
    ] {
        section.retain_mut(restore_record);
    }
    message.signature = None;
    Some(message)
}

/// `message` as a response to a client over UDP, within `max_size`, the largest that the client
/// accepts: if it doesn't fit, it is truncated to its question, so that the client asks again over
/// TCP.
fn encode_udp(message: &Message, max_size: usize) -> Option<Vec<u8>> {
    let encoded = message.to_vec().ok()?;
    if encoded.len() <= max_size {
        return Some(encoded);
    }
    message.truncate().to_vec().ok()
}

/// `message` as a response to a client over TCP, which holds at most [`MAX_MESSAGE_SIZE`].
fn encode_tcp(message: &Message, _: usize) -> Option<Vec<u8>> {
    message
        .to_vec()
        .ok()
        .filter(|encoded| encoded.len() <= MAX_MESSAGE_SIZE)
}

/// A response to `query` with `code` and no records, echoing its question if it has one, or
/// nothing if not even its header can be read.
fn error_response(query: &[u8], code: ResponseCode) -> Vec<u8> {
    let message = match Message::from_vec(query) {
        Ok(query) => {
            let mut response = Message::error_msg(query.metadata.id, query.metadata.op_code, code);
            response.metadata.recursion_desired = query.metadata.recursion_desired;
            response.queries = query.queries;
            response
        },
        Err(_) if query.len() >= 2 => Message::error_msg(
            u16::from_be_bytes([query[0], query[1]]),
            OpCode::Query,
            code,
        ),
        Err(_) => return vec![],
    };
    message.to_vec().unwrap_or_default()
}

/// Answers `query`, received over the transport that `exchange` forwards it by and that `encode`
/// encodes the response for, or returns nothing to send.
async fn answer(
    names: &RwLock<Names>,
    query: &[u8],
    exchange: impl AsyncFnOnce(SocketAddr, Vec<u8>, Instant) -> io::Result<Vec<u8>>,
    encode: fn(&Message, usize) -> Option<Vec<u8>>,
) -> Vec<u8> {
    let forwarded = {
        let names = names.read().unwrap_or_else(PoisonError::into_inner);
        match forward_query(&names, query) {
            Ok(forwarded) => forwarded,
            Err(response) => return response,
        }
    };
    let response = match exchange(
        forwarded.forward.nameserver,
        forwarded.query.clone(),
        Instant::now() + UPSTREAM_DEADLINE,
    )
    .await
    {
        Ok(response) => response,
        Err(e) => {
            log::debug!(
                "the nameserver {} for {} failed to answer: {e}",
                forwarded.forward.nameserver,
                forwarded.forward.hostname
            );
            return error_response(query, ResponseCode::ServFail);
        },
    };
    restore_response(&forwarded, &response)
        .and_then(|message| encode(&message, forwarded.max_udp_size))
        .unwrap_or_else(|| error_response(query, ResponseCode::ServFail))
}

/// The response to `message`, the standard query `query` of one question, for a name that no host
/// nor forward of `names` holds: within the zone, it doesn't exist, but for the zone itself, which
/// has no record that the DNS server answers; outside it, it is refused.
fn not_found(names: &Names, message: &Message, query: &[u8]) -> Vec<u8> {
    let name = message.queries[0].name();
    if !names.zone.zone_of(name) {
        return error_response(query, ResponseCode::Refused);
    }
    let code = match name == &names.zone {
        true => ResponseCode::NoError,
        false => ResponseCode::NXDomain,
    };
    authoritative(message, query, code)
}

/// An authoritative response to `message` with `code` and no records.
fn authoritative(message: &Message, query: &[u8], code: ResponseCode) -> Vec<u8> {
    let mut response = authoritative_response(message);
    response.metadata.response_code = code;
    response
        .to_vec()
        .unwrap_or_else(|_| error_response(query, ResponseCode::ServFail))
}

/// An authoritative response to `message`, echoing its question, without records yet.
fn authoritative_response(message: &Message) -> Message {
    let mut response = Message::response(message.metadata.id, OpCode::Query);
    response.metadata.authoritative = true;
    response.metadata.recursion_desired = message.metadata.recursion_desired;
    response.queries = message.queries.clone();
    response
}

/// `operation`, or an error if it doesn't complete by `deadline`.
async fn by<T>(deadline: Instant, operation: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout_at(deadline, operation)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the deadline passed"))?
}

async fn exchange_udp(
    nameserver: SocketAddr,
    query: Vec<u8>,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    let bind: SocketAddr = match nameserver {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(nameserver).await?;
    socket.send(&query).await?;
    let mut buffer = vec![0; MAX_MESSAGE_SIZE];
    loop {
        let read = by(deadline, socket.recv(&mut buffer)).await?;
        // A response to another query, such as a late one, is skipped.
        if read >= 2 && query.len() >= 2 && buffer[..2] == query[..2] {
            buffer.truncate(read);
            return Ok(buffer);
        }
    }
}

async fn exchange_tcp(
    nameserver: SocketAddr,
    query: Vec<u8>,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    let mut stream = by(deadline, TcpStream::connect(nameserver)).await?;
    write_tcp_message(&mut stream, &query, deadline).await?;
    read_tcp_message(&mut stream, deadline)
        .await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no response"))
}

/// Fills `buffer` from `stream` by `deadline`, however the bytes trickle in. Returns `false` if the
/// stream ends before the first byte.
async fn read_by(stream: &mut TcpStream, buffer: &mut [u8], deadline: Instant) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buffer.len() {
        match by(deadline, stream.read(&mut buffer[filled..])).await? {
            0 if filled == 0 => return Ok(false),
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            read => filled += read,
        }
    }
    Ok(true)
}

/// Reads a length-prefixed message by `deadline`, or `None` at the end of the stream.
async fn read_tcp_message(
    stream: &mut TcpStream,
    deadline: Instant,
) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0; 2];
    if !read_by(stream, &mut length, deadline).await? {
        return Ok(None);
    }
    let mut message = vec![0; usize::from(u16::from_be_bytes(length))];
    if !read_by(stream, &mut message, deadline).await? && !message.is_empty() {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(Some(message))
}

/// Writes a length-prefixed message by `deadline`.
async fn write_tcp_message(
    stream: &mut TcpStream,
    message: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    let length = u16::try_from(message.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message too long"))?;
    let mut framed = length.to_be_bytes().to_vec();
    framed.extend_from_slice(message);
    by(deadline, stream.write_all(&framed)).await
}

/// The lowest port that a user without privileges may bind, as the system says, or
/// [`UNPRIVILEGED_PORT_START`] where it doesn't.
fn unprivileged_port_start() -> u16 {
    #[cfg(target_os = "linux")]
    if let Some(port) = fs::read_to_string("/proc/sys/net/ipv4/ip_unprivileged_port_start")
        .ok()
        .and_then(|start| start.trim().parse().ok())
    {
        return port;
    }
    UNPRIVILEGED_PORT_START
}

/// A slot among the [`MAX_IN_FLIGHT`] queries that the DNS server answers at a time, which it
/// frees when dropped.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(in_flight: &Arc<AtomicUsize>) -> Option<Self> {
        let slot = Self(in_flight.clone());
        // A slot taken beyond the limit is freed again as it drops.
        (in_flight.fetch_add(1, Ordering::AcqRel) < MAX_IN_FLIGHT).then_some(slot)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A running DNS server, which stops when [`Server::stop`] is called or it is dropped.
pub struct Server {
    /// The address at which it answers over both UDP and TCP.
    pub listen: SocketAddr,
    names: Arc<RwLock<Names>>,
    listeners: Vec<JoinHandle<()>>,
}

impl Server {
    /// Listens for queries at `listen` over both UDP and TCP, answering them from `names`, in
    /// tasks of the current runtime. An unspecified address, `0.0.0.0` or `[::]`, listens at
    /// every address of its family, and `[::]` at those of IPv4 too unless the system binds IPv6
    /// sockets to IPv6 alone. A listen address with port 0 takes the port that the system assigns
    /// the UDP socket for both.
    ///
    /// A listen address that isn't a loopback address is warned of: anyone who can reach it can
    /// query the peers' nameservers through this node, and use it to reflect traffic. So is a
    /// port that a user without privileges may bind: whenever the DNS server isn't listening, a
    /// local user can listen there instead, and answer for the peers' names to every resolver
    /// that queries the DNS server.
    pub fn spawn(listen: SocketAddr, names: Names) -> io::Result<Self> {
        let udp = std::net::UdpSocket::bind(listen)?;
        let listen = udp.local_addr()?;
        let tcp = std::net::TcpListener::bind(listen)?;
        if !listen.ip().is_loopback() {
            log::warn!(
                "the DNS server listens at {listen}, which isn't a loopback address: anyone who \
                 can reach it can query the nameservers of peers through it."
            );
        }
        let unprivileged = unprivileged_port_start();
        if listen.port() >= unprivileged {
            log::warn!(
                "the DNS server listens at {listen}, at a port that any user may bind, since it \
                 isn't below {unprivileged}: whenever the DNS server isn't listening, a local user \
                 can answer in its place for the names of peers. A port below {unprivileged}, \
                 such as 53 at an address of 127.0.0.0/8 of its own, can't be taken so."
            );
        }
        udp.set_nonblocking(true)?;
        tcp.set_nonblocking(true)?;
        let udp = Arc::new(UdpSocket::from_std(udp)?);
        let tcp = TcpListener::from_std(tcp)?;

        let names = Arc::new(RwLock::new(names));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let listeners = vec![
            tokio::spawn(serve_udp(udp, names.clone(), in_flight.clone())),
            tokio::spawn(serve_tcp(tcp, names.clone(), in_flight)),
        ];
        Ok(Self {
            listen,
            names,
            listeners,
        })
    }

    /// Replaces the names that the DNS server answers from. A query sees either the old names or
    /// the new ones, never a mix of them.
    pub fn set_names(&self, names: Names) {
        *self.names.write().unwrap_or_else(PoisonError::into_inner) = names;
    }

    /// Stops listening, and returns once the listeners have closed their sockets. Queries that
    /// are being answered finish by their deadlines.
    pub async fn stop(mut self) {
        for listener in self.listeners.drain(..) {
            listener.abort();
            let _ = listener.await;
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        for listener in &self.listeners {
            listener.abort();
        }
    }
}

async fn serve_udp(udp: Arc<UdpSocket>, names: Arc<RwLock<Names>>, in_flight: Arc<AtomicUsize>) {
    let mut buffer = vec![0; MAX_MESSAGE_SIZE];
    loop {
        let (read, client) = match udp.recv_from(&mut buffer).await {
            Ok(received) => received,
            Err(e) => {
                log::warn!("the DNS server failed to receive a query: {e}");
                continue;
            },
        };
        let query = buffer[..read].to_vec();
        let Some(slot) = Slot::take(&in_flight) else {
            let _ = udp
                .send_to(&error_response(&query, ResponseCode::Refused), client)
                .await;
            continue;
        };
        let (socket, names) = (udp.clone(), names.clone());
        tokio::spawn(async move {
            let _slot = slot;
            let response = answer(&names, &query, exchange_udp, encode_udp).await;
            if !response.is_empty() {
                let _ = socket.send_to(&response, client).await;
            }
        });
    }
}

async fn serve_tcp(tcp: TcpListener, names: Arc<RwLock<Names>>, in_flight: Arc<AtomicUsize>) {
    loop {
        let mut stream = match tcp.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                log::warn!("the DNS server failed to accept a connection: {e}");
                continue;
            },
        };
        // A connection beyond the limit is closed at once.
        let Some(slot) = Slot::take(&in_flight) else {
            continue;
        };
        let names = names.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let deadline = Instant::now() + CLIENT_DEADLINE;
            while let Ok(Some(query)) = read_tcp_message(&mut stream, deadline).await {
                let response = answer(&names, &query, exchange_tcp, encode_tcp).await;
                if response.is_empty()
                    || write_tcp_message(&mut stream, &response, deadline)
                        .await
                        .is_err()
                {
                    break;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::{Edns, Query},
        rr::{
            rdata::{A, AAAA, CNAME, MX, NULL, SOA, SRV, TXT},
            RecordType,
        },
    };

    fn name(name: &str) -> Name {
        Name::from_ascii(name).unwrap()
    }

    fn forward() -> Forward {
        Forward {
            hostname: name("b.e2e.wg."),
            zone: name("example.com."),
            nameserver: "10.66.1.33:53".parse().unwrap(),
            delegation: vec!["10.66.1.0/24".parse().unwrap()],
        }
    }

    fn query(qname: &str) -> Vec<u8> {
        query_of(qname, RecordType::A)
    }

    fn query_of(qname: &str, query_type: RecordType) -> Vec<u8> {
        let mut message = Message::query();
        message.metadata.id = 4242;
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(name(qname), query_type));
        message.to_vec().unwrap()
    }

    /// The names of `forwards` alone, without hosts, in the zone e2e.wg.
    fn only(forwards: Vec<Forward>) -> Names {
        Names {
            zone: name("e2e.wg."),
            forwards,
            ..Default::default()
        }
    }

    fn response_code(response: &[u8]) -> ResponseCode {
        Message::from_vec(response).unwrap().metadata.response_code
    }

    fn record(owner: &str, data: RData) -> Record {
        Record::from_rdata(name(owner), 60, data)
    }

    /// The response of a nameserver to `query`, as forwarded, with `answers`.
    fn nameserver_response(forwarded: &Forwarded, answers: Vec<Record>) -> Vec<u8> {
        let mut response = Message::from_vec(&forwarded.query).unwrap();
        response.metadata.message_type = MessageType::Response;
        response.answers = answers;
        response.to_vec().unwrap()
    }

    #[test]
    fn test_forwards() {
        let interface: InterfaceName = "e2e".parse().unwrap();
        let peer = |name: &str, nameserver: Option<&str>| PeerContents {
            name: Some(name.parse().unwrap()),
            delegations: vec!["10.66.1.0/24".parse().unwrap()],
            public_key: wireguard_control::KeyPair::generate().public.to_base64(),
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
            nameserver: nameserver.map(|address| innernet_shared::announcement::Nameserver {
                address: address.parse().unwrap(),
                zone: "example.com".into(),
            }),
        };
        let mut disabled = peer("c", Some("10.66.1.34:53"));
        disabled.is_disabled = true;
        let peers = [
            peer("a", None),
            peer("b", Some("10.66.1.33:53")),
            disabled,
            peer("d", Some("10.66.1.35:53")),
        ];
        let forwarding = |selectors: &[&str]| {
            Forwarding(
                selectors
                    .iter()
                    .map(|selector| selector.to_string().try_into().unwrap())
                    .collect(),
            )
        };
        let hostnames = |forwarding: &Forwarding| {
            forwards(&interface, None, forwarding, &peers)
                .into_iter()
                .map(|forward| forward.hostname)
                .collect::<Vec<_>>()
        };

        // By default, the DNS server forwards to no peer.
        assert!(hostnames(&Forwarding::default()).is_empty());
        let all = forwarding(&["*"]);
        assert_eq!(
            forwards(&interface, None, &all, &peers)[0],
            Forward {
                hostname: name("b.e2e.wg."),
                ..forward()
            }
        );
        assert_eq!(hostnames(&all), [name("b.e2e.wg."), name("d.e2e.wg.")]);
        // A peer selected by name or left out by name, and a disabled peer, never.
        assert_eq!(hostnames(&forwarding(&["d", "c"])), [name("d.e2e.wg.")]);
        assert_eq!(hostnames(&forwarding(&["*", "!b"])), [name("d.e2e.wg.")]);
        assert_eq!(
            forwards(&interface, Some("lan"), &all, &peers)[0].hostname,
            name("b.lan.")
        );
    }

    #[test]
    fn test_hosts() {
        let interface: InterfaceName = "e2e".parse().unwrap();
        let names: BTreeMap<String, IpAddr> = [
            ("a".to_string(), "10.66.1.1".parse().unwrap()),
            ("08".to_string(), "fd00::8".parse().unwrap()),
        ]
        .into();
        assert_eq!(
            hosts(&interface, None, &names),
            [
                (name("08.e2e.wg."), "fd00::8".parse().unwrap()),
                (name("a.e2e.wg."), "10.66.1.1".parse().unwrap()),
            ]
            .into()
        );
        assert_eq!(
            hosts(&interface, Some("lan"), &names)
                .keys()
                .collect::<Vec<_>>(),
            [&name("08.lan."), &name("a.lan.")]
        );
    }

    #[test]
    fn test_answers_for_hosts() {
        let names = Names {
            zone: name("e2e.wg."),
            hosts: [
                (name("c.e2e.wg."), "10.66.2.1".parse().unwrap()),
                (name("d.e2e.wg."), "fd00::1".parse().unwrap()),
                (name("x.b.e2e.wg."), "10.66.1.40".parse().unwrap()),
            ]
            .into(),
            forwards: vec![forward()],
        };
        let respond = |qname: &str, query_type| {
            Message::from_vec(&forward_query(&names, &query_of(qname, query_type)).unwrap_err())
                .unwrap()
        };

        // The address of a host's own name, under the name as the client spelled it.
        let response = respond("C.e2e.wg.", RecordType::A);
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.metadata.authoritative);
        assert_eq!(response.metadata.id, 4242);
        assert!(response.metadata.recursion_desired);
        assert!(response.queries[0].name().eq_case(&name("C.e2e.wg.")));
        assert!(response.answers[0].name.eq_case(&name("C.e2e.wg.")));
        assert_eq!(response.answers[0].data, RData::A(A::new(10, 66, 2, 1)));
        assert_eq!(response.answers[0].ttl, HOST_TTL);
        assert_eq!(
            respond("d.e2e.wg.", RecordType::AAAA).answers[0].data,
            RData::AAAA(AAAA::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(respond("c.e2e.wg.", RecordType::ANY).answers.len(), 1);

        // Any other type of record of a host, an address of the other family included, is none.
        for (qname, query_type) in [
            ("c.e2e.wg.", RecordType::AAAA),
            ("c.e2e.wg.", RecordType::TXT),
            ("d.e2e.wg.", RecordType::A),
        ] {
            let response = respond(qname, query_type);
            assert_eq!(response.metadata.response_code, ResponseCode::NoError);
            assert!(response.answers.is_empty(), "{qname} {query_type}");
        }

        // A name under a host doesn't exist, also where the host is named under a peer that offers
        // a nameserver: the nameserver answers for that peer's names, not for those of the host.
        for qname in ["www.c.e2e.wg.", "www.x.b.e2e.wg."] {
            let response = respond(qname, RecordType::A);
            assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
            assert!(response.metadata.authoritative);
        }
        assert_eq!(
            respond("x.b.e2e.wg.", RecordType::A).answers[0].data,
            RData::A(A::new(10, 66, 1, 40))
        );
        let forwarded = forward_query(&names, &query("www.b.e2e.wg.")).unwrap();
        assert_eq!(forwarded.forwarded_name, name("www.example.com."));
    }

    #[test]
    fn test_forward_takes_precedence_over_host() {
        // A peer that offers a nameserver is a host too: its nameserver answers for its hostname
        // while the DNS server forwards to it, and the DNS server itself otherwise.
        let host = (name("b.e2e.wg."), "10.66.1.33".parse().unwrap());
        let forwarded = Names {
            zone: name("e2e.wg."),
            hosts: [host.clone()].into(),
            forwards: vec![forward()],
        };
        let forwarded = forward_query(&forwarded, &query("b.e2e.wg.")).unwrap();
        assert_eq!(forwarded.forwarded_name, name("example.com."));

        let not_forwarded = Names {
            zone: name("e2e.wg."),
            hosts: [host].into(),
            forwards: vec![],
        };
        let response = forward_query(&not_forwarded, &query("b.e2e.wg.")).unwrap_err();
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(response.answers[0].data, RData::A(A::new(10, 66, 1, 33)));
        let response = forward_query(&not_forwarded, &query("www.b.e2e.wg.")).unwrap_err();
        assert_eq!(response_code(&response), ResponseCode::NXDomain);
    }

    #[test]
    fn test_replace_suffix() {
        let (from, to) = (name("b.e2e.wg."), name("example.com."));
        assert_eq!(
            replace_suffix(&name("www.b.e2e.wg."), &from, &to),
            Some(name("www.example.com."))
        );
        assert_eq!(
            replace_suffix(&name("x.y.B.E2E.wg."), &from, &to),
            Some(name("x.y.example.com."))
        );
        assert_eq!(
            replace_suffix(&name("b.e2e.wg."), &from, &to),
            Some(to.clone())
        );
        assert_eq!(replace_suffix(&name("c.e2e.wg."), &from, &to), None);
        assert_eq!(replace_suffix(&name("ab.e2e.wg."), &from, &to), None);
        assert_eq!(replace_suffix(&name("e2e.wg."), &from, &to), None);
    }

    #[test]
    fn test_forwards_hostname_and_names_under_it() {
        let forwards = only(vec![forward()]);
        for (qname, forwarded) in [
            ("b.e2e.wg.", "example.com."),
            ("www.b.e2e.wg.", "www.example.com."),
            ("a.b.c.B.e2e.WG.", "a.b.c.example.com."),
        ] {
            let result = forward_query(&forwards, &query(qname)).unwrap();
            let message = Message::from_vec(&result.query).unwrap();
            assert_eq!(message.metadata.id, 4242);
            assert!(message.queries[0].name().eq_case(&name(forwarded)));
            assert!(result.name.eq_case(&name(qname)));
            assert_eq!(result.max_udp_size, 512);
        }
    }

    #[test]
    fn test_longest_match_wins() {
        // A peer named under another's name answers for its own names, in whatever order the
        // forwards come.
        let inner = Forward {
            hostname: name("x.b.e2e.wg."),
            zone: name("example.org."),
            nameserver: "10.66.2.33:53".parse().unwrap(),
            delegation: vec!["10.66.2.32/28".parse().unwrap()],
        };
        for forwards in [[forward(), inner.clone()], [inner.clone(), forward()]] {
            let forwards = only(forwards.to_vec());
            let routed = forward_query(&forwards, &query("www.x.b.e2e.wg.")).unwrap();
            assert_eq!(routed.forward, inner);
            assert_eq!(routed.forwarded_name, name("www.example.org."));
            let routed = forward_query(&forwards, &query("www.b.e2e.wg.")).unwrap();
            assert_eq!(routed.forward, forward());
        }
    }

    #[test]
    fn test_refuses_other_names_and_other_queries() {
        let forwards = only(vec![forward()]);
        let respond = |qname: &str| {
            let response = forward_query(&forwards, &query(qname)).unwrap_err();
            let response = Message::from_vec(&response).unwrap();
            assert_eq!(response.metadata.id, 4242);
            assert_eq!(response.queries[0].name(), &name(qname));
            response
        };
        // The DNS server is authoritative for its zone: a name in it that no peer has, such as
        // that of a disabled peer, doesn't exist, and the zone itself has no record that it
        // answers.
        let response = respond("c.e2e.wg.");
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        assert!(response.metadata.authoritative);
        let response = respond("e2e.wg.");
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.metadata.authoritative);
        assert!(response.answers.is_empty());
        // A name outside the zone is refused.
        for qname in ["example.com.", "b.e2e.wg.example.com.", "wg."] {
            assert_eq!(
                respond(qname).metadata.response_code,
                ResponseCode::Refused,
                "{qname}"
            );
        }

        // Only standard queries are forwarded: an update or a notification isn't.
        for op_code in [OpCode::Update, OpCode::Notify, OpCode::Status] {
            let mut message = Message::from_vec(&query("www.b.e2e.wg.")).unwrap();
            message.metadata.op_code = op_code;
            let response = forward_query(&forwards, &message.to_vec().unwrap()).unwrap_err();
            assert_eq!(
                response_code(&response),
                ResponseCode::NotImp,
                "{op_code:?}"
            );
        }
        // A response is never answered, so that two DNS servers can't bounce one between them.
        let mut message = Message::from_vec(&query("www.b.e2e.wg.")).unwrap();
        message.metadata.message_type = MessageType::Response;
        assert!(forward_query(&forwards, &message.to_vec().unwrap())
            .unwrap_err()
            .is_empty());

        // Garbage gets a format error with the ID it appears to have, or nothing.
        assert_eq!(
            response_code(&forward_query(&forwards, &[0x10, 0x92, 0xff]).unwrap_err()),
            ResponseCode::FormErr
        );
        assert!(forward_query(&forwards, &[0x10]).unwrap_err().is_empty());
    }

    #[test]
    fn test_restores_names_in_response() {
        let forwards = only(vec![forward()]);
        let forwarded = forward_query(&forwards, &query("WWW.b.e2e.wg.")).unwrap();

        // The nameserver's response, entirely in terms of the zone.
        let mut response = Message::from_vec(&forwarded.query).unwrap();
        response.metadata.message_type = MessageType::Response;
        response.add_answer(record(
            "www.example.com.",
            RData::CNAME(CNAME(name("web.example.com."))),
        ));
        response.add_answer(record("web.example.com.", RData::A(A::new(10, 66, 1, 34))));
        response.add_answer(record(
            "web.example.com.",
            RData::CNAME(CNAME(name("cdn.example.net."))),
        ));
        response.add_authority(record(
            "example.com.",
            RData::SOA(SOA::new(
                name("ns.example.com."),
                name("admin.example.com."),
                1,
                60,
                60,
                60,
                60,
            )),
        ));
        response.additionals.push(record(
            "example.com.",
            RData::MX(MX::new(10, name("mail.example.com."))),
        ));
        response.additionals.push(record(
            "_x._tcp.example.com.",
            RData::SRV(SRV::new(0, 0, 80, name("web.example.com."))),
        ));
        let restored = restore_response(&forwarded, &response.to_vec().unwrap()).unwrap();

        // The question is the client's own, case included.
        assert!(restored.queries[0].name().eq_case(&name("WWW.b.e2e.wg.")));
        assert!(restored.answers[0].name.eq_case(&name("WWW.b.e2e.wg.")));
        assert_eq!(
            restored.answers[0].data,
            RData::CNAME(CNAME(name("web.b.e2e.wg.")))
        );
        assert_eq!(restored.answers[1].name, name("web.b.e2e.wg."));
        assert_eq!(restored.answers[1].data, RData::A(A::new(10, 66, 1, 34)));
        // A name outside the zone in the data of a record is left as it is.
        assert_eq!(
            restored.answers[2].data,
            RData::CNAME(CNAME(name("cdn.example.net.")))
        );
        assert_eq!(restored.authorities[0].name, name("b.e2e.wg."));
        let RData::SOA(soa) = &restored.authorities[0].data else {
            panic!("not an SOA record");
        };
        assert_eq!(soa.mname, name("ns.b.e2e.wg."));
        assert_eq!(soa.rname, name("admin.b.e2e.wg."));
        let RData::MX(mx) = &restored.additionals[0].data else {
            panic!("not an MX record");
        };
        assert_eq!(mx.exchange, name("mail.b.e2e.wg."));
        assert_eq!(restored.additionals[1].name, name("_x._tcp.b.e2e.wg."));
        let RData::SRV(srv) = &restored.additionals[1].data else {
            panic!("not an SRV record");
        };
        assert_eq!(srv.target, name("web.b.e2e.wg."));
    }

    #[test]
    fn test_drops_records_outside_the_zone() {
        // A nameserver can't answer for another peer's name or for any other domain, nor slip in
        // a record of a type whose names the DNS server doesn't restore.
        let forwards = only(vec![forward()]);
        let forwarded = forward_query(&forwards, &query("www.b.e2e.wg.")).unwrap();
        let response = nameserver_response(
            &forwarded,
            vec![
                record("www.example.com.", RData::A(A::new(10, 66, 1, 34))),
                record("a.e2e.wg.", RData::A(A::new(10, 66, 1, 2))),
                record("bank.com.", RData::A(A::new(192, 0, 2, 1))),
                record("example.net.", RData::TXT(TXT::new(vec!["x".into()]))),
                record(
                    "www.example.com.",
                    RData::Unknown {
                        code: RecordType::Unknown(65280),
                        rdata: NULL::with(vec![1, 2, 3]),
                    },
                ),
            ],
        );
        let restored = restore_response(&forwarded, &response).unwrap();
        assert_eq!(
            restored.answers,
            [record("www.b.e2e.wg.", RData::A(A::new(10, 66, 1, 34)))]
        );
    }

    #[test]
    fn test_drops_addresses_outside_the_delegation() {
        // A nameserver can't point a name of the peer at an address that isn't the peer's.
        let forwards = only(vec![forward()]);
        let forwarded = forward_query(&forwards, &query("www.b.e2e.wg.")).unwrap();
        let response = nameserver_response(
            &forwarded,
            vec![
                record("www.example.com.", RData::A(A::new(10, 66, 1, 34))),
                record("www.example.com.", RData::A(A::new(10, 66, 2, 1))),
                record("www.example.com.", RData::A(A::new(192, 0, 2, 1))),
                record(
                    "www.example.com.",
                    RData::AAAA(AAAA::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
                ),
            ],
        );
        let restored = restore_response(&forwarded, &response).unwrap();
        assert_eq!(
            restored.answers,
            [record("www.b.e2e.wg.", RData::A(A::new(10, 66, 1, 34)))]
        );
    }

    #[tokio::test]
    async fn test_answer() {
        let forwards = RwLock::new(only(vec![forward()]));

        // The nameserver sees the zone, and the client its own names.
        let response = answer(
            &forwards,
            &query("www.b.e2e.wg."),
            async |nameserver, query: Vec<u8>, deadline| {
                assert_eq!(nameserver, forward().nameserver);
                assert!(deadline > Instant::now());
                let mut response = Message::from_vec(&query).unwrap();
                assert_eq!(response.queries[0].name(), &name("www.example.com."));
                response.metadata.message_type = MessageType::Response;
                response.add_answer(record("www.example.com.", RData::A(A::new(10, 66, 1, 34))));
                Ok(response.to_vec().unwrap())
            },
            encode_udp,
        )
        .await;
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(response.answers[0].name, name("www.b.e2e.wg."));

        // A nameserver that fails to answer, or answers garbage, is a server failure.
        let failed = answer(
            &forwards,
            &query("www.b.e2e.wg."),
            async |_, _, _| Err(io::Error::new(io::ErrorKind::TimedOut, "timed out")),
            encode_udp,
        )
        .await;
        assert_eq!(response_code(&failed), ResponseCode::ServFail);
        let garbage = answer(
            &forwards,
            &query("www.b.e2e.wg."),
            async |_, _, _| Ok(vec![1, 2, 3]),
            encode_udp,
        )
        .await;
        assert_eq!(response_code(&garbage), ResponseCode::ServFail);

        // Other names never reach a nameserver.
        let unknown = answer(
            &forwards,
            &query("c.e2e.wg."),
            async |_, _, _| panic!("forwarded a query for another name"),
            encode_udp,
        )
        .await;
        assert_eq!(response_code(&unknown), ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn test_responses_fit_the_client() {
        // A response that outgrows what the client accepts over UDP once its names are restored
        // is truncated, so that the client asks again over TCP.
        let forward = Forward {
            hostname: name("a-rather-long-peer-name.with.a-long.host-suffix.wg."),
            ..forward()
        };
        let forwards = RwLock::new(only(vec![forward]));
        let many = |query: &[u8]| {
            let mut response = Message::from_vec(query).unwrap();
            response.metadata.message_type = MessageType::Response;
            for i in 0..20 {
                response.add_answer(record(
                    &format!("host{i}.example.com."),
                    RData::A(A::new(10, 66, 1, i)),
                ));
            }
            response
        };
        let qname = "www.a-rather-long-peer-name.with.a-long.host-suffix.wg.";
        let probe = forward_query(&forwards.read().unwrap(), &query(qname)).unwrap();
        assert!(many(&probe.query).to_vec().unwrap().len() <= 512);

        let udp = answer(
            &forwards,
            &query(qname),
            async |_, query: Vec<u8>, _| Ok(many(&query).to_vec().unwrap()),
            encode_udp,
        )
        .await;
        assert!(udp.len() <= 512);
        let udp = Message::from_vec(&udp).unwrap();
        assert!(udp.metadata.truncation);
        assert!(udp.answers.is_empty());

        // A client that accepts more over EDNS gets it all, and so does one over TCP.
        let mut large = Message::from_vec(&query(qname)).unwrap();
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        large.set_edns(edns);
        let large = answer(
            &forwards,
            &large.to_vec().unwrap(),
            async |_, query: Vec<u8>, _| Ok(many(&query).to_vec().unwrap()),
            encode_udp,
        )
        .await;
        assert_eq!(Message::from_vec(&large).unwrap().answers.len(), 20);
        let tcp = answer(
            &forwards,
            &query(qname),
            async |_, query: Vec<u8>, _| Ok(many(&query).to_vec().unwrap()),
            encode_tcp,
        )
        .await;
        assert_eq!(Message::from_vec(&tcp).unwrap().answers.len(), 20);
    }

    #[test]
    fn test_slots() {
        let in_flight = Arc::new(AtomicUsize::new(0));
        let slots: Vec<Slot> = (0..MAX_IN_FLIGHT)
            .map(|_| Slot::take(&in_flight).unwrap())
            .collect();
        assert!(Slot::take(&in_flight).is_none());
        drop(slots);
        assert_eq!(in_flight.load(Ordering::Acquire), 0);
        assert!(Slot::take(&in_flight).is_some());
    }

    #[tokio::test]
    async fn test_deadlines() {
        // A nameserver that never answers is given up on by the deadline.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let started = Instant::now();
        let deadline = started + Duration::from_millis(300);
        let result = exchange_udp(silent.local_addr().unwrap(), query("x."), deadline).await;
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));

        // And one that trickles a byte at a time can't hold a connection past it either.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let trickler = std::thread::spawn(move || {
            use std::io::Write as _;
            let (mut stream, _) = listener.accept().unwrap();
            for _ in 0..20 {
                if stream.write_all(&[0xff]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let started = Instant::now();
        let deadline = started + Duration::from_millis(300);
        let result = exchange_tcp(address, query("x."), deadline).await;
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        trickler.join().unwrap();
    }

    /// Exchanges `query` for a response over a TCP connection of a client, framed by length.
    fn tcp_exchange(stream: &mut std::net::TcpStream, query: &[u8]) -> Vec<u8> {
        use std::io::{Read as _, Write as _};
        let mut framed = (query.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(query);
        stream.write_all(&framed).unwrap();
        let mut length = [0; 2];
        stream.read_exact(&mut length).unwrap();
        let mut response = vec![0; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut response).unwrap();
        response
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_round_trips() {
        // A nameserver that answers every query with one A record, under the queried name, over
        // UDP and TCP.
        let respond = |query: &[u8]| {
            let mut response = Message::from_vec(query).unwrap();
            response.metadata.message_type = MessageType::Response;
            let qname = response.queries[0].name().clone();
            response.add_answer(Record::from_rdata(
                qname,
                60,
                RData::A(A::new(10, 66, 1, 34)),
            ));
            response.to_vec().unwrap()
        };
        let nameserver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let nameserver_addr = nameserver.local_addr().unwrap();
        let nameserver_tcp = std::net::TcpListener::bind(nameserver_addr).unwrap();
        std::thread::spawn(move || {
            let mut buffer = [0; 512];
            let (read, client) = nameserver.recv_from(&mut buffer).unwrap();
            nameserver
                .send_to(&respond(&buffer[..read]), client)
                .unwrap();
        });
        std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};
            let (mut stream, _) = nameserver_tcp.accept().unwrap();
            let mut length = [0; 2];
            stream.read_exact(&mut length).unwrap();
            let mut query = vec![0; usize::from(u16::from_be_bytes(length))];
            stream.read_exact(&mut query).unwrap();
            let response = respond(&query);
            let mut framed = (response.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&response);
            stream.write_all(&framed).unwrap();
        });

        // The DNS server takes the same port for UDP and TCP when the system assigns it.
        let server = Server::spawn(
            "127.0.0.1:0".parse().unwrap(),
            Names {
                zone: name("e2e.wg."),
                hosts: [(name("c.e2e.wg."), "10.66.2.1".parse().unwrap())].into(),
                forwards: vec![Forward {
                    nameserver: nameserver_addr,
                    ..forward()
                }],
            },
        )
        .unwrap();
        let listen = server.listen;
        assert_ne!(listen.port(), 0);

        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_read_timeout(Some(UPSTREAM_DEADLINE)).unwrap();
        client.send_to(&query("www.b.e2e.wg."), listen).unwrap();
        let mut buffer = [0; 512];
        let read = client.recv(&mut buffer).unwrap();
        let response = Message::from_vec(&buffer[..read]).unwrap();
        assert_eq!(response.metadata.id, 4242);
        assert_eq!(response.answers[0].name, name("www.b.e2e.wg."));
        assert_eq!(response.answers[0].data, RData::A(A::new(10, 66, 1, 34)));

        let mut stream = std::net::TcpStream::connect(listen).unwrap();
        stream.set_read_timeout(Some(UPSTREAM_DEADLINE)).unwrap();
        let response = tcp_exchange(&mut stream, &query("www.b.e2e.wg."));
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(response.answers[0].name, name("www.b.e2e.wg."));

        // The DNS server answers for a peer that offers no nameserver itself.
        client.send_to(&query("c.e2e.wg."), listen).unwrap();
        let read = client.recv(&mut buffer).unwrap();
        let response = Message::from_vec(&buffer[..read]).unwrap();
        assert_eq!(response.answers[0].data, RData::A(A::new(10, 66, 2, 1)));

        // New names take effect at once, and a stopped server releases its address.
        server.set_names(Names {
            zone: name("e2e.wg."),
            ..Default::default()
        });
        client.send_to(&query("www.b.e2e.wg."), listen).unwrap();
        let read = client.recv(&mut buffer).unwrap();
        assert_eq!(response_code(&buffer[..read]), ResponseCode::NXDomain);
        drop(stream);
        server.stop().await;
        let again = Server::spawn(listen, Names::default()).unwrap();
        again.stop().await;
    }
}
