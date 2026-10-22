#![feature(ip)]

use ipnet::IpNet;
use std::{
    fs::{self, File, Permissions},
    io,
    net::IpAddr,
    os::unix::fs::PermissionsExt,
    path::Path,
    time::Duration,
};
use wireguard_control::InterfaceName;

pub mod announcement;
pub mod cbor;
pub mod interface_config;
pub mod media_type;
#[cfg(target_os = "linux")]
mod netlink;
pub mod peer;
pub mod prefix;
pub mod problem;
pub mod prompts;
pub mod tls;
pub mod types;
pub mod wg;
pub mod xeddsa;

pub use anyhow::Error;
pub use prefix::{
    check_delegations, cidr_of_delegations, hosts_fallback, parent_cidr, smallest_cidr_holding,
    Prefix,
};
pub use types::*;

pub const REDEEM_TRANSITION_WAIT: Duration = Duration::from_secs(5);
pub const PERSISTENT_KEEPALIVE_INTERVAL_SECS: u16 = 25;
pub const INNERNET_PUBKEY_HEADER: &str = "X-Innernet-Server-Key";

pub fn ensure_dirs_exist(dirs: &[&Path]) -> Result<(), WrappedIoError> {
    for dir in dirs {
        match fs::create_dir(dir).with_path(dir) {
            Ok(()) => {
                log::debug!("created dir {}", dir.to_string_lossy());
                std::fs::set_permissions(dir, Permissions::from_mode(0o700)).with_path(dir)?;
            },
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // Directory already exists, good.
            },
            Err(e) => {
                return Err(e);
            },
        }
    }
    Ok(())
}

/// Warns if `file` is world-accessible. The permissions are read from the open file, so that they
/// are those of the file that the caller uses; `path` is only used in the warning.
pub fn warn_on_dangerous_mode(file: &File, path: &Path) -> Result<(), io::Error> {
    let metadata = file.metadata()?;
    let permissions = metadata.permissions();
    let mode = permissions.mode() & 0o777;

    if mode & 0o007 != 0 {
        log::warn!(
            "{} is world-accessible (mode is {:#05o}). This is probably not what you want.",
            path.to_string_lossy(),
            mode
        );
    }
    Ok(())
}

/// Updates the permissions of a file or directory. Returns `Ok(true)` if
/// permissions had to be changed, `Ok(false)` if permissions were already
/// correct.
pub fn chmod(file: &File, new_mode: u32) -> Result<bool, io::Error> {
    let metadata = file.metadata()?;
    let mut permissions = metadata.permissions();
    let mode = permissions.mode() & 0o777;
    let updated = if mode != new_mode {
        permissions.set_mode(new_mode);
        file.set_permissions(permissions)?;
        true
    } else {
        false
    };

    Ok(updated)
}

#[cfg(any(target_os = "macos", target_os = "openbsd"))]
pub fn _get_local_addrs() -> Result<impl Iterator<Item = std::net::IpAddr>, io::Error> {
    use std::net::Ipv4Addr;

    use nix::net::if_::InterfaceFlags;

    let addrs = nix::ifaddrs::getifaddrs()?
        .filter(|addr| {
            addr.flags.contains(InterfaceFlags::IFF_UP)
                && !addr.flags.intersects(
                    InterfaceFlags::IFF_LOOPBACK
                        | InterfaceFlags::IFF_POINTOPOINT
                        | InterfaceFlags::IFF_PROMISC,
                )
        })
        .filter_map(|interface_addr| {
            interface_addr.address.and_then(|addr| {
                if let Some(sockaddr_in) = addr.as_sockaddr_in() {
                    Some(IpAddr::V4(Ipv4Addr::from(sockaddr_in.ip())))
                } else {
                    addr.as_sockaddr_in6()
                        .map(|sockaddr_in6| IpAddr::V6(sockaddr_in6.ip()))
                }
            })
        });

    Ok(addrs)
}

#[cfg(target_os = "linux")]
pub use netlink::get_local_addrs as _get_local_addrs;

pub fn get_local_addrs() -> Result<impl Iterator<Item = std::net::IpAddr>, io::Error> {
    Ok(_get_local_addrs()?
        .filter(|ip| match ip {
            IpAddr::V4(_) => true,
            IpAddr::V6(v6) => v6.is_unicast_global(),
        })
        .take(10))
}

pub trait IpNetExt {
    fn is_assignable(&self, ip: &IpAddr) -> bool;
}

impl IpNetExt for IpNet {
    fn is_assignable(&self, ip: &IpAddr) -> bool {
        self.contains(ip)
            && match self {
                IpNet::V4(_) => {
                    self.prefix_len() >= 31 || (ip != &self.network() && ip != &self.broadcast())
                },
                IpNet::V6(_) => self.prefix_len() >= 127 || ip != &self.network(),
            }
    }
}

/// The zone of the names of the peers of `interface`: the host suffix that the operator chooses,
/// or `<interface>.wg`.
pub fn peer_zone(interface: &InterfaceName, host_suffix: Option<&str>) -> String {
    match host_suffix {
        Some(suffix) => suffix.to_string(),
        None => format!("{interface}.wg"),
    }
}

/// The hostname of the peer `name`, its name in the zone of [`peer_zone`], or `None` if the peer
/// has none: a peer name that isn't a valid hostname, such as one with a newline or a space, names
/// no host.
pub fn peer_hostname(
    interface: &InterfaceName,
    host_suffix: Option<&str>,
    name: &str,
) -> Option<String> {
    Hostname::is_valid(name).then(|| format!("{name}.{}", peer_zone(interface, host_suffix)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_hostname() {
        let interface: InterfaceName = "wg0".parse().unwrap();
        let hostname = |suffix, name| peer_hostname(&interface, suffix, name);

        assert_eq!(hostname(None, "peer-1").as_deref(), Some("peer-1.wg0.wg"));
        assert_eq!(
            hostname(Some("evilnet"), "peer-1").as_deref(),
            Some("peer-1.evilnet")
        );

        // A name that a suffix follows may contain dots and end in a number.
        assert_eq!(hostname(None, "08").as_deref(), Some("08.wg0.wg"));
        assert_eq!(
            hostname(Some("evilnet"), "a.08").as_deref(),
            Some("a.08.evilnet")
        );

        // A name that isn't a valid hostname is omitted.
        assert_eq!(hostname(None, "peer\n10.0.0.1 example.com"), None);
        assert_eq!(hostname(None, "a b"), None);
        assert_eq!(hostname(None, "Peer"), None);
        assert_eq!(hostname(None, ""), None);
        assert_eq!(
            hostname(None, "4CNZorWVtohO64n6AAaH/JyFjIIgBFrfJK2SGtKjzEE="),
            None
        );
    }
}
