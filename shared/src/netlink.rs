use ipnet::IpNet;
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_REPLACE,
    NLM_F_REQUEST,
};
use netlink_packet_route::{
    address::{self, AddressHeader, AddressHeaderFlags, AddressMessage},
    link::{self, LinkFlags, LinkHeader, LinkMessage},
    route::{self, RouteHeader, RouteMessage},
    AddressFamily, RouteNetlinkMessage,
};
use netlink_request::netlink_request_rtnl;
use std::{io, net::IpAddr};
use wireguard_control::InterfaceName;

fn if_nametoindex(interface: &InterfaceName) -> Result<u32, io::Error> {
    match unsafe { libc::if_nametoindex(interface.as_ptr()) } {
        0 => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("couldn't find interface '{interface}'."),
        )),
        index => Ok(index),
    }
}

pub fn set_up(interface: &InterfaceName, mtu: u32) -> Result<(), io::Error> {
    let index = if_nametoindex(interface)?;
    let header = LinkHeader {
        index,
        flags: LinkFlags::Up,
        ..Default::default()
    };
    let mut message = LinkMessage::default();
    message.header = header;
    message.attributes = vec![link::LinkAttribute::Mtu(mtu)];
    netlink_request_rtnl(RouteNetlinkMessage::SetLink(message), None)?;
    log::debug!("set interface {} up with mtu {}", interface, mtu);
    Ok(())
}

pub fn set_addr(interface: &InterfaceName, addr: IpNet) -> Result<(), io::Error> {
    let index = if_nametoindex(interface)?;
    let (family, nlas) = match addr {
        IpNet::V4(network) => {
            let addr = IpAddr::V4(network.addr());
            (
                AddressFamily::Inet,
                vec![
                    address::AddressAttribute::Local(addr),
                    address::AddressAttribute::Address(addr),
                ],
            )
        },
        IpNet::V6(network) => (
            AddressFamily::Inet6,
            vec![address::AddressAttribute::Address(IpAddr::V6(
                network.addr(),
            ))],
        ),
    };
    let header = AddressHeader {
        index,
        family,
        prefix_len: addr.prefix_len(),
        scope: address::AddressScope::Universe,
        ..Default::default()
    };

    let mut message = AddressMessage::default();
    message.header = header;
    message.attributes = nlas;
    netlink_request_rtnl(
        RouteNetlinkMessage::NewAddress(message),
        Some(NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE | NLM_F_CREATE),
    )?;
    log::debug!("set address {} on interface {}", addr, interface);
    Ok(())
}

pub fn add_route(interface: &InterfaceName, cidr: IpNet) -> Result<bool, io::Error> {
    let if_index = if_nametoindex(interface)?;
    let (address_family, dst) = match cidr {
        IpNet::V4(network) => (
            AddressFamily::Inet,
            route::RouteAttribute::Destination(route::RouteAddress::Inet(network.network())),
        ),
        IpNet::V6(network) => (
            AddressFamily::Inet6,
            route::RouteAttribute::Destination(route::RouteAddress::Inet6(network.network())),
        ),
    };
    let header = RouteHeader {
        table: RouteHeader::RT_TABLE_MAIN,
        protocol: route::RouteProtocol::Boot,
        scope: route::RouteScope::Link,
        kind: route::RouteType::Unicast,
        destination_prefix_length: cidr.prefix_len(),
        address_family,
        ..Default::default()
    };
    let mut message = RouteMessage::default();
    message.header = header;
    message.attributes = vec![dst, route::RouteAttribute::Oif(if_index)];

    match netlink_request_rtnl(RouteNetlinkMessage::NewRoute(message), None) {
        Ok(_) => {
            log::debug!("added route {} to interface {}", cidr, interface);
            Ok(true)
        },
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            log::debug!("route {} already existed.", cidr);
            Ok(false)
        },
        Err(e) => Err(e),
    }
}

/// Whether a link's flags make its addresses worth offering to other peers: the link is up and has
/// a carrier, and is neither a loopback nor a point-to-point link, such as a WireGuard or other
/// tunnel interface, whose addresses are reached only through the tunnel. The operational state
/// isn't consulted, since many drivers, virtual ones in particular, report it as unknown.
fn is_offered_link(flags: LinkFlags) -> bool {
    flags.contains(LinkFlags::Up | LinkFlags::LowerUp)
        && !flags.intersects(LinkFlags::Loopback | LinkFlags::Pointopoint)
}

/// Whether an address's header makes it worth offering to other peers. A temporary IPv6 address,
/// flagged as secondary, is left out, since it rotates and would change what the host announces
/// every time; so are addresses that are deprecated, or not yet or never usable after duplicate
/// address detection. An IPv4 address flagged as secondary is an ordinary address and is kept.
fn is_offered_address(header: &AddressHeader) -> bool {
    let unusable = AddressHeaderFlags::Deprecated
        | AddressHeaderFlags::Tentative
        | AddressHeaderFlags::Dadfailed;
    header.scope == address::AddressScope::Universe
        && !header.flags.intersects(unusable)
        && !(header.family == AddressFamily::Inet6
            && header.flags.contains(AddressHeaderFlags::Secondary))
}

/// The indices of the links whose addresses are worth offering, as [`is_offered_link`] decides.
fn get_offered_links() -> Result<Vec<u32>, io::Error> {
    let link_responses = netlink_request_rtnl(
        RouteNetlinkMessage::GetLink(LinkMessage::default()),
        Some(NLM_F_DUMP | NLM_F_REQUEST),
    )?;
    let links = link_responses
        .into_iter()
        // Filter out non-link messages
        .filter_map(|response| match response {
            NetlinkMessage {
                payload: NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)),
                ..
            } => Some(link.header),
            _ => None,
        })
        .filter(|header| is_offered_link(header.flags))
        .map(|header| header.index)
        .collect::<Vec<_>>();

    Ok(links)
}

pub fn get_local_addrs() -> Result<impl Iterator<Item = IpAddr>, io::Error> {
    let links = get_offered_links()?;
    let addr_responses = netlink_request_rtnl(
        RouteNetlinkMessage::GetAddress(AddressMessage::default()),
        Some(NLM_F_DUMP | NLM_F_REQUEST),
    )?;
    let addrs = addr_responses
        .into_iter()
        // Filter out non-link messages
        .filter_map(|response| match response {
            NetlinkMessage {
                payload: NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(addr)),
                ..
            } => Some(addr),
            _ => None,
        })
        // Only select usable addresses of helpful links. The link is matched by its index, since
        // only IPv4 addresses carry the link's name as a label.
        .filter(move |addr| links.contains(&addr.header.index) && is_offered_address(&addr.header))
        .map(|addr| addr.attributes)
        .filter_map(|nlas| {
            nlas.iter().find_map(|nla| match nla {
                address::AddressAttribute::Address(IpAddr::V4(addr)) => Some(IpAddr::V4(*addr)),
                address::AddressAttribute::Address(IpAddr::V6(addr)) => Some(IpAddr::V6(*addr)),
                _ => None,
            })
        });
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_addrs() {
        let addrs = get_local_addrs().unwrap();
        println!("{:?}", addrs.collect::<Vec<_>>());
    }

    #[test]
    fn test_is_offered_link() {
        let ethernet = LinkFlags::Up | LinkFlags::LowerUp | LinkFlags::Broadcast;
        assert!(is_offered_link(ethernet));
        assert!(is_offered_link(ethernet | LinkFlags::Running));
        // Down, or without a carrier.
        assert!(!is_offered_link(LinkFlags::LowerUp | LinkFlags::Broadcast));
        assert!(!is_offered_link(LinkFlags::Up | LinkFlags::Broadcast));
        // A WireGuard interface, and the loopback.
        assert!(!is_offered_link(
            LinkFlags::Up | LinkFlags::LowerUp | LinkFlags::Pointopoint | LinkFlags::Noarp
        ));
        assert!(!is_offered_link(
            LinkFlags::Up | LinkFlags::LowerUp | LinkFlags::Loopback
        ));
    }

    #[test]
    fn test_is_offered_address() {
        let header = |family, flags| AddressHeader {
            family,
            flags,
            scope: address::AddressScope::Universe,
            ..Default::default()
        };
        let permanent = AddressHeaderFlags::Permanent;
        assert!(is_offered_address(&header(AddressFamily::Inet, permanent)));
        assert!(is_offered_address(&header(AddressFamily::Inet6, permanent)));
        // A secondary IPv4 address is kept, a temporary IPv6 address isn't.
        let secondary = AddressHeaderFlags::Secondary;
        assert!(is_offered_address(&header(AddressFamily::Inet, secondary)));
        assert!(!is_offered_address(&header(
            AddressFamily::Inet6,
            secondary
        )));
        for unusable in [
            AddressHeaderFlags::Deprecated,
            AddressHeaderFlags::Tentative,
            AddressHeaderFlags::Dadfailed,
        ] {
            assert!(!is_offered_address(&header(AddressFamily::Inet, unusable)));
            assert!(!is_offered_address(&header(AddressFamily::Inet6, unusable)));
        }
        let link_local = AddressHeader {
            scope: address::AddressScope::Link,
            ..header(AddressFamily::Inet6, permanent)
        };
        assert!(!is_offered_address(&link_local));
    }
}
