//! The watcher of the host's addresses, which wakes the node when they change, since the node's
//! candidates are the endpoints at those addresses. On Linux, the kernel pushes each change of an
//! address to a netlink socket subscribed to them; elsewhere, the watcher polls the addresses.
//!
//! The kernel also reports an address whose lifetimes are only refreshed, as each router
//! advertisement does to the addresses of SLAAC, so the watcher compares the addresses that the
//! host offers before and after a report, and wakes the node only when they differ.

use innernet_shared::get_local_addrs;
use std::{collections::BTreeSet, io, net::IpAddr, time::Duration};

/// Watches the addresses of the host.
pub struct Watcher {
    inner: imp::Watcher,
    /// How long the watcher gathers the changes of a burst, such as those of a link that comes
    /// up, before it reports them as one.
    settle: Duration,
    /// The addresses that the host offered when the watcher last looked.
    addresses: BTreeSet<IpAddr>,
}

impl Watcher {
    pub fn new(settle: Duration) -> io::Result<Self> {
        Ok(Self {
            inner: imp::Watcher::new()?,
            settle,
            addresses: get_local_addrs()?.collect(),
        })
    }

    /// Waits until the addresses that the host offers change, and then settle.
    pub async fn changed(&mut self) -> io::Result<()> {
        loop {
            self.inner.changed().await?;
            tokio::time::sleep(self.settle).await;
            self.inner.drain()?;
            let addresses: BTreeSet<IpAddr> = get_local_addrs()?.collect();
            if addresses != self.addresses {
                self.addresses = addresses;
                return Ok(());
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::{
        io, mem,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
    };
    use tokio::io::unix::AsyncFd;

    /// A netlink socket subscribed to the changes of IPv4 and IPv6 addresses.
    pub struct Watcher {
        socket: AsyncFd<OwnedFd>,
    }

    impl Watcher {
        pub fn new() -> io::Result<Self> {
            // SAFETY: the arguments are valid, and the returned descriptor is checked.
            let fd = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    libc::NETLINK_ROUTE,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `fd` is a descriptor that nothing else owns.
            let socket = unsafe { OwnedFd::from_raw_fd(fd) };
            // SAFETY: sockaddr_nl is plain data, for which zero is a valid value.
            let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
            address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            address.nl_groups = (libc::RTMGRP_IPV4_IFADDR | libc::RTMGRP_IPV6_IFADDR) as u32;
            // SAFETY: `address` is a valid sockaddr_nl of the length given.
            let bound = unsafe {
                libc::bind(
                    socket.as_raw_fd(),
                    &address as *const libc::sockaddr_nl as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if bound < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                socket: AsyncFd::new(socket)?,
            })
        }

        /// Waits until the kernel reports a change.
        pub async fn changed(&mut self) -> io::Result<()> {
            loop {
                let mut guard = self.socket.readable().await?;
                match guard.try_io(|socket| read(socket.get_ref())) {
                    Ok(Ok(0)) => continue,
                    Ok(Ok(_)) => return Ok(()),
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => continue,
                }
            }
        }

        /// Discards the reports that are queued, which the change already reported covers.
        pub fn drain(&mut self) -> io::Result<()> {
            loop {
                match read(self.socket.get_ref()) {
                    Ok(_) => {},
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                    Err(e) => return Err(e),
                }
            }
        }
    }

    /// Reads one message of `socket`, whose content the watcher doesn't need.
    fn read(socket: &OwnedFd) -> io::Result<usize> {
        let mut buffer = [0u8; 8192];
        // SAFETY: the buffer is valid for its length.
        let read = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
            )
        };
        match read {
            // A buffer that the kernel couldn't fill still reports a change.
            _ if read < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOBUFS) => {
                Ok(1)
            },
            _ if read < 0 => Err(io::Error::last_os_error()),
            read => Ok(read as usize),
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::{io, time::Duration};

    const POLL_INTERVAL: Duration = Duration::from_secs(10);

    /// A timer at which the addresses of the host are polled, which [`super::Watcher`] compares.
    pub struct Watcher;

    impl Watcher {
        pub fn new() -> io::Result<Self> {
            Ok(Self)
        }

        pub async fn changed(&mut self) -> io::Result<()> {
            tokio::time::sleep(POLL_INTERVAL).await;
            Ok(())
        }

        pub fn drain(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_watcher_opens() {
        // Opening the socket needs no privilege; nothing changes the addresses here, so no change
        // is reported.
        let mut watcher = Watcher::new(Duration::from_millis(200)).unwrap();
        let changed = tokio::time::timeout(Duration::from_millis(50), watcher.changed()).await;
        assert!(changed.is_err());
    }
}
