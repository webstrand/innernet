//! The DNS server, which answers for the names of the peers.
//!
//! Every node runs the same DNS server, a client and the server alike, from the peers of its
//! snapshot, as [`crate::realize::DnsServer`] publishes them. The server is authoritative for its
//! zone, the host suffix or `<interface>.wg` by default: it answers a query for the hostname of an
//! enabled peer, as this node names it, with the peer's address, one for the apex of the zone
//! with no record, and one for any other name of the zone, a disabled peer's or one under a
//! peer's hostname included, with NXDOMAIN. It refuses queries for names outside the zone.
//!
//! The DNS server answers over UDP and TCP at the same address. It runs at most
//! [`MAX_IN_FLIGHT`] queries at a time and refuses the rest, and gives each TCP connection of a
//! client [`CLIENT_DEADLINE`] in all, however slowly it sends.

use crate::snapshot::Snapshot;
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{Name, RData, Record, RecordType},
};
use innernet_shared::{host_zone, peer_hostname};
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

/// What the DNS server answers for: its zone, if it has one, and the hostname of each enabled
/// peer that has one, with its address.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Names {
    pub zone: Option<Name>,
    pub hosts: BTreeMap<Name, IpAddr>,
}

impl Names {
    /// The names that `snapshot` publishes for `interface`, in the zone of `host_suffix`, as
    /// [`host_zone`] makes it: the hostnames of the enabled peers that have a name and an address
    /// to name, at their hosts fallback addresses.
    pub fn of(interface: &InterfaceName, host_suffix: Option<&str>, snapshot: &Snapshot) -> Self {
        let peers = snapshot
            .peers
            .iter()
            .filter(|peer| !peer.is_disabled)
            .filter_map(|peer| Some((peer.name.as_ref()?.to_string(), peer.hosts_fallback()?)));
        Self {
            zone: fqdn(&host_zone(interface, host_suffix)),
            hosts: hosts(interface, host_suffix, peers),
        }
    }
}

/// The hostnames of `peers`, each a peer's name with its address, under `host_suffix`, as
/// [`peer_hostname`] makes them. A peer whose name gives no hostname is left out.
pub fn hosts(
    interface: &InterfaceName,
    host_suffix: Option<&str>,
    peers: impl IntoIterator<Item = (String, IpAddr)>,
) -> BTreeMap<Name, IpAddr> {
    peers
        .into_iter()
        .filter_map(|(name, ip)| {
            let hostname = peer_hostname(interface, host_suffix, &name).and_then(|h| fqdn(&h));
            if hostname.is_none() {
                log::debug!(
                    "not answering for the peer named {}, whose name gives no hostname.",
                    name.escape_debug()
                );
            }
            Some((hostname?, ip))
        })
        .collect()
}

fn fqdn(name: &str) -> Option<Name> {
    let mut name = Name::from_ascii(name).ok()?;
    name.set_fqdn(true);
    Some(name)
}

/// The response to `query`: the address of the hostname of a peer, as [`host_response`] answers
/// it, no record for the apex of the zone, NXDOMAIN for another name of the zone, or a refusal of
/// a query that isn't a standard query of one question, or of one for a name outside the zone. A
/// response to a response is nothing.
fn respond(names: &Names, query: &[u8]) -> Vec<u8> {
    let Ok(message) = Message::from_vec(query) else {
        return error_response(query, ResponseCode::FormErr);
    };
    if message.metadata.message_type != MessageType::Query {
        return vec![];
    }
    if message.metadata.op_code != OpCode::Query {
        return error_response(query, ResponseCode::NotImp);
    }
    if message.queries.len() != 1 {
        return error_response(query, ResponseCode::Refused);
    }
    let name = message.queries[0].name();
    if let Some(ip) = names.hosts.get(name) {
        return host_response(&message, query, *ip);
    }
    match &names.zone {
        Some(zone) if zone == name => authoritative(&message, query, ResponseCode::NoError),
        Some(zone) if zone.zone_of(name) => authoritative(&message, query, ResponseCode::NXDomain),
        _ => error_response(query, ResponseCode::Refused),
    }
}

/// The authoritative response to `message`, the standard query `query` of one question, with
/// `code` and no records.
fn authoritative(message: &Message, query: &[u8], code: ResponseCode) -> Vec<u8> {
    let mut response = Message::error_msg(message.metadata.id, message.metadata.op_code, code);
    response.metadata.authoritative = true;
    response.metadata.recursion_desired = message.metadata.recursion_desired;
    response.queries = message.queries.clone();
    response
        .to_vec()
        .unwrap_or_else(|_| error_response(query, ResponseCode::ServFail))
}

/// The response to `message`, the standard query `query` of one question, for the hostname of a
/// peer whose address is `ip`: the address if the query asks for one of its family, or for any
/// type, and no record otherwise. The response is authoritative, and small enough for any client
/// over UDP.
fn host_response(message: &Message, query: &[u8], ip: IpAddr) -> Vec<u8> {
    let question = &message.queries[0];
    let mut response = Message::response(message.metadata.id, OpCode::Query);
    response.metadata.authoritative = true;
    response.metadata.recursion_desired = message.metadata.recursion_desired;
    response.queries = message.queries.clone();
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

fn answer(names: &RwLock<Names>, query: &[u8]) -> Vec<u8> {
    let names = names.read().unwrap_or_else(PoisonError::into_inner);
    respond(&names, query)
}

/// `operation`, or an error if it doesn't complete by `deadline`.
async fn by<T>(deadline: Instant, operation: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout_at(deadline, operation)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the deadline passed"))?
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
    /// learn the peers' names and addresses through it, and use it to reflect traffic. So is a
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
                 can reach it can learn the names of peers through it."
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
        let query = &buffer[..read];
        let response = match Slot::take(&in_flight) {
            Some(_slot) => answer(&names, query),
            None => error_response(query, ResponseCode::Refused),
        };
        if !response.is_empty() {
            let _ = udp.send_to(&response, client).await;
        }
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
                let response = answer(&names, &query);
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
    use hickory_proto::op::Query;

    fn name(name: &str) -> Name {
        fqdn(name).unwrap()
    }

    fn query_of(qname: &str, query_type: RecordType) -> Vec<u8> {
        let mut message = Message::query();
        message.metadata.id = 7;
        message.add_query(Query::query(name(qname), query_type));
        message.to_vec().unwrap()
    }

    fn response_code(response: &[u8]) -> ResponseCode {
        Message::from_vec(response).unwrap().metadata.response_code
    }

    fn names() -> Names {
        Names {
            zone: Some(name("wg0.wg")),
            hosts: [
                (name("a.wg0.wg"), "10.0.0.2".parse().unwrap()),
                (name("v6.wg0.wg"), "fd00::2".parse().unwrap()),
            ]
            .into(),
        }
    }

    #[test]
    fn test_names_of() {
        let interface: InterfaceName = "wg0".parse().unwrap();
        let peer = |name: &str, ip: &str, is_disabled| innernet_shared::PeerContents {
            name: name.parse().ok(),
            delegations: vec![innernet_shared::Prefix::host(ip.parse().unwrap())],
            public_key: wireguard_control::KeyPair::generate().public.to_base64(),
            endpoint: None,
            persistent_keepalive_interval: None,
            is_admin: false,
            is_disabled,
            is_redeemed: true,
            invite_expires: None,
            candidates: vec![],
        };
        let snapshot = crate::snapshot::snapshot([
            peer("a", "10.0.0.2", false),
            peer("off", "10.0.0.3", true),
            peer("Not Valid", "10.0.0.4", false),
        ]);

        // The enabled peers that have a name, in the zone of the interface or of the suffix.
        assert_eq!(Names::of(&interface, None, &snapshot), {
            Names {
                zone: Some(name("wg0.wg")),
                hosts: [(name("a.wg0.wg"), "10.0.0.2".parse().unwrap())].into(),
            }
        });
        let corp = Names::of(&interface, Some("corp"), &snapshot);
        assert_eq!(corp.zone, Some(name("corp")));
        assert_eq!(corp.hosts.into_keys().collect::<Vec<_>>(), [name("a.corp")]);
    }

    #[test]
    fn test_respond() {
        let names = names();
        // The address of a peer's hostname, of its family.
        let response =
            Message::from_vec(&respond(&names, &query_of("a.wg0.wg", RecordType::A))).unwrap();
        assert!(response.metadata.authoritative);
        assert_eq!(response.metadata.id, 7);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(
            response.answers[0].data,
            RData::A("10.0.0.2".parse::<std::net::Ipv4Addr>().unwrap().into())
        );
        // No record of another family.
        let response =
            Message::from_vec(&respond(&names, &query_of("a.wg0.wg", RecordType::AAAA))).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty());
        // The apex of the zone exists, with no record.
        let response =
            Message::from_vec(&respond(&names, &query_of("wg0.wg", RecordType::A))).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.metadata.authoritative);
        assert!(response.answers.is_empty());
        // Another name of the zone, such as a disabled peer's or one under a hostname, doesn't
        // exist.
        for missing in ["off.wg0.wg", "www.a.wg0.wg"] {
            let response =
                Message::from_vec(&respond(&names, &query_of(missing, RecordType::A))).unwrap();
            assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
            assert!(response.metadata.authoritative);
        }
        // A name outside the zone is refused.
        for refused in ["example.com", "wg"] {
            assert_eq!(
                response_code(&respond(&names, &query_of(refused, RecordType::A))),
                ResponseCode::Refused
            );
        }
        // A message that isn't one is refused as malformed.
        assert_eq!(
            response_code(&respond(&names, &[0, 7, 0])),
            ResponseCode::FormErr
        );
    }

    #[tokio::test]
    async fn test_server_answers_over_udp_and_tcp() {
        let server = Server::spawn("127.0.0.1:0".parse().unwrap(), Names::default()).unwrap();
        server.set_names(names());
        let query = query_of("v6.wg0.wg", RecordType::AAAA);

        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.send_to(&query, server.listen).await.unwrap();
        let mut buffer = vec![0; MAX_MESSAGE_SIZE];
        let read = udp.recv(&mut buffer).await.unwrap();
        let response = Message::from_vec(&buffer[..read]).unwrap();
        assert_eq!(response.answers.len(), 1);

        let mut stream = TcpStream::connect(server.listen).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        write_tcp_message(&mut stream, &query, deadline)
            .await
            .unwrap();
        let response = read_tcp_message(&mut stream, deadline)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(Message::from_vec(&response).unwrap().answers.len(), 1);
        server.stop().await;
    }
}
