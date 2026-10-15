//! A forwarder of DNS queries for the names of peers that offer a nameserver.
//!
//! A peer that offers a nameserver announces it together with the zone it answers for. The
//! forwarder answers queries for the hostname of such a peer, and for the names under it, by
//! replacing the hostname with the zone, forwarding the query to the peer's nameserver, and
//! replacing the zone with the hostname again in the response. Queries for other names are
//! refused, so that the forwarder only ever speaks for the peers' own names.

use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::{Name, RData},
};
use innernet_shared::{peer_hostname, Peer};
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::{Arc, RwLock},
    thread,
    time::Duration,
};
use wireguard_control::InterfaceName;

/// How long to wait for a peer's nameserver to answer.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// The largest response accepted from a nameserver over UDP.
const MAX_UDP_SIZE: usize = 65535;

/// The hostname of a peer that offers a nameserver, and where queries for it go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forward {
    /// The peer's hostname, as the hosts file would name it.
    pub hostname: Name,
    /// The zone that the nameserver answers for in place of `hostname`.
    pub zone: Name,
    pub nameserver: SocketAddr,
}

/// The forwards of an interface, which the forwarder reads for every query and the daemon
/// replaces on every fetch.
pub type Forwards = Arc<RwLock<Vec<Forward>>>;

/// The forwards for the enabled peers of `peers` that have a name and offer a nameserver, with
/// their hostnames under `host_suffix` as the hosts file would write them.
pub fn forwards(
    interface: &InterfaceName,
    host_suffix: Option<&str>,
    peers: &[Peer],
) -> Vec<Forward> {
    peers
        .iter()
        .filter(|peer| !peer.is_disabled)
        .filter_map(|peer| {
            let dns = peer.announced_dns()?;
            let hostname = peer_hostname(interface, host_suffix, peer.name.as_ref()?)?;
            Some(Forward {
                hostname: fqdn(&hostname)?,
                zone: fqdn(&dns.zone)?,
                nameserver: dns.nameserver,
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

/// A query as forwarded to a nameserver, with what is needed to restore the response.
#[derive(Debug)]
struct Forwarded {
    /// The query, with the hostname replaced by the zone.
    query: Vec<u8>,
    /// The name queried by the client, as the client spelled it.
    name: Name,
    /// The name as forwarded.
    forwarded_name: Name,
    forward: Forward,
}

/// Prepares `query` for forwarding, or returns the response to send back instead.
fn forward_query(forwards: &[Forward], query: &[u8]) -> Result<Forwarded, Vec<u8>> {
    let Ok(mut message) = Message::from_vec(query) else {
        return Err(error_response(query, ResponseCode::FormErr));
    };
    if message.metadata.message_type != MessageType::Query || message.queries.len() != 1 {
        return Err(error_response(query, ResponseCode::Refused));
    }
    let name = message.queries[0].name().clone();
    let routed = forwards.iter().find_map(|forward| {
        replace_suffix(&name, &forward.hostname, &forward.zone).map(|zone| (forward, zone))
    });
    let Some((forward, forwarded_name)) = routed else {
        return Err(error_response(query, ResponseCode::Refused));
    };
    message.queries[0].set_name(forwarded_name.clone());
    match message.to_vec() {
        Ok(query) => Ok(Forwarded {
            query,
            name,
            forwarded_name,
            forward: forward.clone(),
        }),
        Err(_) => Err(error_response(query, ResponseCode::ServFail)),
    }
}

/// Restores the names of a nameserver's `response` to what the client asked about: the queried
/// name as the client spelled it, and the zone replaced by the hostname in every other name
/// within it, whether it owns a record or appears in its data. Names outside the zone are left
/// as they are.
fn restore_response(forwarded: &Forwarded, response: &[u8]) -> Option<Vec<u8>> {
    let mut message = Message::from_vec(response).ok()?;
    let Forward { hostname, zone, .. } = &forwarded.forward;
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
    for record in message
        .answers
        .iter_mut()
        .chain(message.authorities.iter_mut())
        .chain(message.additionals.iter_mut())
    {
        restore(&mut record.name);
        match &mut record.data {
            RData::CNAME(data) => restore(&mut data.0),
            RData::NS(data) => restore(&mut data.0),
            RData::PTR(data) => restore(&mut data.0),
            RData::ANAME(data) => restore(&mut data.0),
            RData::MX(data) => restore(&mut data.exchange),
            RData::SRV(data) => restore(&mut data.target),
            RData::SOA(data) => {
                restore(&mut data.mname);
                restore(&mut data.rname);
            },
            _ => {},
        }
    }
    message.to_vec().ok()
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
            hickory_proto::op::OpCode::Query,
            code,
        ),
        Err(_) => return vec![],
    };
    message.to_vec().unwrap_or_default()
}

/// Answers `query`, received over the transport that `exchange` forwards it by.
fn answer(
    forwards: &Forwards,
    query: &[u8],
    exchange: impl FnOnce(SocketAddr, &[u8]) -> io::Result<Vec<u8>>,
) -> Vec<u8> {
    let forwards = forwards.read().unwrap().clone();
    let forwarded = match forward_query(&forwards, query) {
        Ok(forwarded) => forwarded,
        Err(response) => return response,
    };
    let response = match exchange(forwarded.forward.nameserver, &forwarded.query) {
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
        .unwrap_or_else(|| error_response(query, ResponseCode::ServFail))
}

fn exchange_udp(nameserver: SocketAddr, query: &[u8]) -> io::Result<Vec<u8>> {
    let bind: SocketAddr = match nameserver {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let socket = UdpSocket::bind(bind)?;
    socket.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    socket.connect(nameserver)?;
    socket.send(query)?;
    let mut buffer = vec![0; MAX_UDP_SIZE];
    loop {
        let read = socket.recv(&mut buffer)?;
        // A response to another query, such as a late one, is skipped.
        if read >= 2 && query.len() >= 2 && buffer[..2] == query[..2] {
            buffer.truncate(read);
            return Ok(buffer);
        }
    }
}

fn exchange_tcp(nameserver: SocketAddr, query: &[u8]) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(&nameserver, UPSTREAM_TIMEOUT)?;
    stream.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    stream.set_write_timeout(Some(UPSTREAM_TIMEOUT))?;
    write_tcp_message(&mut stream, query)?;
    read_tcp_message(&mut stream)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no response"))
}

/// Reads a length-prefixed message, or `None` at the end of the stream.
fn read_tcp_message(stream: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0; 2];
    match stream.read_exact(&mut length) {
        Ok(()) => {},
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let mut message = vec![0; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut message)?;
    Ok(Some(message))
}

fn write_tcp_message(stream: &mut impl Write, message: &[u8]) -> io::Result<()> {
    let length = u16::try_from(message.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message too long"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(message)
}

/// Listens for queries on `listen` over both UDP and TCP, answering them from `forwards` on
/// threads of their own.
pub fn spawn(listen: SocketAddr, forwards: Forwards) -> io::Result<()> {
    let udp = UdpSocket::bind(listen)?;
    let tcp = TcpListener::bind(listen)?;

    let udp_forwards = forwards.clone();
    thread::spawn(move || {
        let mut buffer = vec![0; MAX_UDP_SIZE];
        loop {
            let (read, client) = match udp.recv_from(&mut buffer) {
                Ok(received) => received,
                Err(e) => {
                    log::warn!("the DNS forwarder failed to receive a query: {e}");
                    continue;
                },
            };
            let query = buffer[..read].to_vec();
            let (Ok(socket), forwards) = (udp.try_clone(), udp_forwards.clone()) else {
                continue;
            };
            thread::spawn(move || {
                let response = answer(&forwards, &query, exchange_udp);
                if !response.is_empty() {
                    let _ = socket.send_to(&response, client);
                }
            });
        }
    });

    thread::spawn(move || {
        for stream in tcp.incoming() {
            let Ok(mut stream) = stream else {
                continue;
            };
            let forwards = forwards.clone();
            thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
                while let Ok(Some(query)) = read_tcp_message(&mut stream) {
                    let response = answer(&forwards, &query, exchange_tcp);
                    if response.is_empty() || write_tcp_message(&mut stream, &response).is_err() {
                        break;
                    }
                }
            });
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::Query,
        rr::{
            rdata::{A, CNAME, MX, SOA, SRV},
            Record, RecordType,
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
        }
    }

    fn query(qname: &str) -> Vec<u8> {
        let mut message = Message::query();
        message.metadata.id = 4242;
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(name(qname), RecordType::A));
        message.to_vec().unwrap()
    }

    fn response_code(response: &[u8]) -> ResponseCode {
        Message::from_vec(response).unwrap().metadata.response_code
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
        let forwards = [forward()];
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
        }
    }

    #[test]
    fn test_refuses_other_names() {
        let forwards = [forward()];
        for qname in [
            "c.e2e.wg.",
            "e2e.wg.",
            "example.com.",
            "b.e2e.wg.example.com.",
        ] {
            let response = forward_query(&forwards, &query(qname)).unwrap_err();
            assert_eq!(response_code(&response), ResponseCode::Refused);
            let response = Message::from_vec(&response).unwrap();
            assert_eq!(response.metadata.id, 4242);
            assert_eq!(response.queries[0].name(), &name(qname));
        }
        assert_eq!(
            response_code(&forward_query(&[], &query("b.e2e.wg.")).unwrap_err()),
            ResponseCode::Refused
        );
        // Garbage gets a format error with the ID it appears to have, or nothing.
        assert_eq!(
            response_code(&forward_query(&forwards, &[0x10, 0x92, 0xff]).unwrap_err()),
            ResponseCode::FormErr
        );
        assert!(forward_query(&forwards, &[0x10]).unwrap_err().is_empty());
    }

    #[test]
    fn test_restores_names_in_response() {
        let forwards = [forward()];
        let forwarded = forward_query(&forwards, &query("WWW.b.e2e.wg.")).unwrap();

        // The nameserver's response, entirely in terms of the zone.
        let mut response = Message::from_vec(&forwarded.query).unwrap();
        response.metadata.message_type = MessageType::Response;
        let record = |owner: &str, data: RData| Record::from_rdata(name(owner), 60, data);
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
        response.add_additional(record(
            "example.com.",
            RData::MX(MX::new(10, name("mail.example.com."))),
        ));
        response.add_additional(record(
            "_x._tcp.example.com.",
            RData::SRV(SRV::new(0, 0, 80, name("web.example.com."))),
        ));
        let restored = restore_response(&forwarded, &response.to_vec().unwrap()).unwrap();
        let restored = Message::from_vec(&restored).unwrap();

        // The question is the client's own, case included.
        assert!(restored.queries[0].name().eq_case(&name("WWW.b.e2e.wg.")));
        let answers: Vec<_> = restored.answers.iter().map(|r| r.to_string()).collect();
        assert!(restored.answers[0].name.eq_case(&name("WWW.b.e2e.wg.")));
        assert_eq!(
            restored.answers[0].data,
            RData::CNAME(CNAME(name("web.b.e2e.wg.")))
        );
        assert_eq!(restored.answers[1].name, name("web.b.e2e.wg."));
        assert_eq!(restored.answers[1].data, RData::A(A::new(10, 66, 1, 34)));
        // A name outside the zone is left as it is.
        assert_eq!(
            restored.answers[2].data,
            RData::CNAME(CNAME(name("cdn.example.net."))),
            "{answers:?}"
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
    fn test_answer() {
        let forwards: Forwards = Arc::new(RwLock::new(vec![forward()]));

        // The nameserver sees the zone, and the client its own names.
        let response = answer(&forwards, &query("www.b.e2e.wg."), |nameserver, query| {
            assert_eq!(nameserver, forward().nameserver);
            let mut response = Message::from_vec(query).unwrap();
            assert_eq!(response.queries[0].name(), &name("www.example.com."));
            response.metadata.message_type = MessageType::Response;
            response.add_answer(Record::from_rdata(
                name("www.example.com."),
                60,
                RData::A(A::new(10, 66, 1, 34)),
            ));
            Ok(response.to_vec().unwrap())
        });
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(response.answers[0].name, name("www.b.e2e.wg."));

        // A nameserver that fails to answer, or answers garbage, is a server failure.
        let failed = answer(&forwards, &query("www.b.e2e.wg."), |_, _| {
            Err(io::Error::new(io::ErrorKind::TimedOut, "timed out"))
        });
        assert_eq!(response_code(&failed), ResponseCode::ServFail);
        let garbage = answer(&forwards, &query("www.b.e2e.wg."), |_, _| Ok(vec![1, 2, 3]));
        assert_eq!(response_code(&garbage), ResponseCode::ServFail);

        // Other names never reach a nameserver.
        let refused = answer(&forwards, &query("c.e2e.wg."), |_, _| {
            panic!("forwarded a query for another name")
        });
        assert_eq!(response_code(&refused), ResponseCode::Refused);
    }

    #[test]
    fn test_tcp_framing() {
        let mut buffer = vec![];
        write_tcp_message(&mut buffer, &[1, 2, 3]).unwrap();
        assert_eq!(buffer, [0, 3, 1, 2, 3]);
        let mut reader = &buffer[..];
        assert_eq!(read_tcp_message(&mut reader).unwrap(), Some(vec![1, 2, 3]));
        assert_eq!(read_tcp_message(&mut reader).unwrap(), None);
    }

    #[test]
    fn test_udp_round_trip() {
        // A nameserver that answers every query with one A record, under the queried name.
        let nameserver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let nameserver_addr = nameserver.local_addr().unwrap();
        thread::spawn(move || {
            let mut buffer = [0; 512];
            let (read, client) = nameserver.recv_from(&mut buffer).unwrap();
            let mut response = Message::from_vec(&buffer[..read]).unwrap();
            response.metadata.message_type = MessageType::Response;
            let qname = response.queries[0].name().clone();
            response.add_answer(Record::from_rdata(
                qname,
                60,
                RData::A(A::new(10, 66, 1, 34)),
            ));
            nameserver
                .send_to(&response.to_vec().unwrap(), client)
                .unwrap();
        });

        let forwards: Forwards = Arc::new(RwLock::new(vec![Forward {
            nameserver: nameserver_addr,
            ..forward()
        }]));
        let listen = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        spawn(listen, forwards).unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_read_timeout(Some(UPSTREAM_TIMEOUT)).unwrap();
        client.send_to(&query("www.b.e2e.wg."), listen).unwrap();
        let mut buffer = [0; 512];
        let read = client.recv(&mut buffer).unwrap();
        let response = Message::from_vec(&buffer[..read]).unwrap();
        assert_eq!(response.metadata.id, 4242);
        assert_eq!(response.answers[0].name, name("www.b.e2e.wg."));
        assert_eq!(response.answers[0].data, RData::A(A::new(10, 66, 1, 34)));
    }
}
