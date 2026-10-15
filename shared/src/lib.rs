use colored::Colorize;
use hostsfile::HostsBuilder;
use ipnet::IpNet;
use std::{
    fs::{self, File, Permissions},
    io,
    net::{IpAddr, Ipv6Addr},
    os::unix::fs::PermissionsExt,
    path::Path,
    time::Duration,
};
use wireguard_control::InterfaceName;

pub mod announcement;
pub mod interface_config;
#[cfg(target_os = "linux")]
mod netlink;
pub mod peer;
pub mod prefix_set;
pub mod prompts;
pub mod tls;
pub mod types;
pub mod wg;
pub mod xeddsa;

pub use anyhow::Error;
pub use types::*;

pub const REDEEM_TRANSITION_WAIT: Duration = Duration::from_secs(5);
pub const PERSISTENT_KEEPALIVE_INTERVAL_SECS: u16 = 25;
pub const INNERNET_PUBKEY_HEADER: &str = "X-Innernet-Server-Key";
pub const DEFAULT_HOSTS_PATH: &str = "/etc/hosts";

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
    // TODO(jake): this is temporary pending the stabilization of rust-lang/rust#27709
    fn is_unicast_global(ip: &Ipv6Addr) -> bool {
        !((ip.segments()[0] & 0xff00) == 0xff00 // multicast
            || ip.is_loopback()
            || ip.is_unspecified()
            || ((ip.segments()[0] == 0x2001) && (ip.segments()[1] == 0xdb8)) // documentation
            || (ip.segments()[0] & 0xffc0) == 0xfe80 // unicast link local
            || (ip.segments()[0] & 0xfe00) == 0xfc00) // unicast local
    }

    Ok(_get_local_addrs()?
        .filter(|ip| {
            ip.is_ipv4()
                || matches!(ip,
            IpAddr::V6(v6) if is_unicast_global(v6))
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

pub fn update_hosts_file(
    interface: &InterfaceName,
    opts: &HostsOpts,
    peers: impl IntoIterator<Item = impl AsRef<Peer>>,
) -> Result<(), WrappedIoError> {
    if opts.no_write_hosts {
        return Ok(());
    }

    let mut hosts_builder = HostsBuilder::new(format!("innernet {interface}"));
    for (ip, hostname) in hosts_entries(interface, opts.host_suffix.as_deref(), peers) {
        hosts_builder.add_hostname(ip, hostname);
    }
    match hosts_builder
        .write_to(opts.hosts_path.as_path())
        .with_path(opts.hosts_path.as_path())
    {
        Ok(has_written) if has_written => {
            log::info!(
                "updated {} with the latest peers.",
                opts.hosts_path.to_string_lossy().yellow()
            )
        },
        Ok(_) => {},
        Err(e) => log::warn!("failed to update hosts ({})", e),
    };

    Ok(())
}

/// The hosts file entries of `peers`, each an address and a hostname.
///
/// A peer without a name has no entry, and neither has a peer that offers a nameserver, which
/// answers for its name instead.
fn hosts_entries(
    interface: &InterfaceName,
    host_suffix: Option<&str>,
    peers: impl IntoIterator<Item = impl AsRef<Peer>>,
) -> Vec<(IpAddr, String)> {
    let mut entries = vec![];
    for peer in peers {
        let peer = peer.as_ref();
        let Some(name) = &peer.contents.name else {
            continue;
        };
        if peer.contents.announced_dns().is_some() {
            continue;
        }
        match peer_hostname(interface, host_suffix, name) {
            Some(peer_hostname) => entries.push((peer.contents.ip, peer_hostname)),
            None => log::warn!(
                "omitting peer {} from the hosts file, since without a host suffix its name is \
                 not a single-label domain.",
                name
            ),
        }
    }
    entries
}

/// The hostname of the peer `name` in the hosts file, or `None` if the peer must be omitted.
///
/// With a suffix, which the operator chooses, the hostname is the peer name followed by the
/// suffix. Without a suffix, the hostname is the peer name alone, which
/// [`innernet_domain::is_canonical_domain`] must accept, so that it does not end in a number. A
/// dotted peer name without a suffix names an arbitrary domain, such as "www.example.com".
pub fn peer_hostname(
    interface: &InterfaceName,
    host_suffix: Option<&str>,
    name: &str,
) -> Option<String> {
    match host_suffix {
        None => Some(format!("{name}.{interface}.wg")),
        Some("") => innernet_domain::is_canonical_domain(name).then(|| name.to_string()),
        Some(suffix) => Some(format!("{name}.{suffix}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_hostname() {
        let interface: InterfaceName = "wg0".parse().unwrap();
        let hostname = |suffix, name| peer_hostname(&interface, suffix, name);

        // A name that a suffix follows may contain dots and end in a number.
        assert_eq!(hostname(None, "08").as_deref(), Some("08.wg0.wg"));
        assert_eq!(
            hostname(Some("evilnet"), "a.08").as_deref(),
            Some("a.08.evilnet")
        );

        // Without a suffix, the name may contain dots but must not end in a number.
        assert_eq!(hostname(Some(""), "peer-1").as_deref(), Some("peer-1"));
        assert_eq!(
            hostname(Some(""), "www.example.com").as_deref(),
            Some("www.example.com")
        );
        assert_eq!(hostname(Some(""), "08"), None);
        assert_eq!(hostname(Some(""), "a.0x7f000001"), None);
    }

    #[test]
    fn test_hosts_entries_omit_peers_offering_dns() {
        let interface: InterfaceName = "wg0".parse().unwrap();
        let peer = |name: Option<&str>, ip: &str, nameserver: Option<&str>| {
            let mut peer: Peer = serde_json::from_value(serde_json::json!({
                "id": 1,
                "name": name,
                "ip": ip,
                "cidr_id": 1,
                "public_key": wireguard_control::KeyPair::generate().public.to_base64(),
                "endpoint": null,
                "persistent_keepalive_interval": null,
                "is_admin": false,
                "is_disabled": false,
                "is_redeemed": true,
                "invite_expires": null,
            }))
            .unwrap();
            peer.contents.announcement = Some(announcement::SignedAnnouncement {
                announcement: announcement::Announcement {
                    timestamp: 1,
                    endpoint: None,
                    candidates: vec![],
                    allow_observed: false,
                    delegations: vec![],
                    dns: nameserver.map(|nameserver| announcement::DnsAnnouncement {
                        nameserver: nameserver.parse().unwrap(),
                        zone: "example.com".into(),
                    }),
                    extensions: vec![],
                },
                signature: vec![],
            });
            peer
        };
        let peers = [
            peer(Some("plain"), "10.0.0.2", None),
            peer(None, "10.0.0.3", None),
            peer(Some("dns"), "10.0.0.4", Some("10.0.0.4:53")),
            // A nameserver that isn't accepted leaves the entry in place.
            peer(Some("elsewhere"), "10.0.0.5", Some("192.0.2.1:53")),
        ];
        assert_eq!(
            hosts_entries(&interface, None, &peers),
            [
                ("10.0.0.2".parse().unwrap(), "plain.wg0.wg".to_string()),
                ("10.0.0.5".parse().unwrap(), "elsewhere.wg0.wg".to_string()),
            ]
        );
    }
}
