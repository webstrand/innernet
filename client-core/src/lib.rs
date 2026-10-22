//! This library can be used to control innernet interfaces.
//!
//! This is a work in progress but the final goal is to match the `innernet` CLI API surface.

pub use innernet_shared::{
    interface_config::Invitation, Association, Cidr, CidrTree, Endpoint, HostsOpts, LegacyPeer,
    NatOpts, NetworkOpts, PeerContents, WrappedIoError,
};
pub use wireguard_control::Backend;

pub mod admin;
pub mod data_store;
pub mod interface;
pub mod peer;
pub mod rest_client;

pub const DEFAULT_CONFIG_DIR: &str = "/etc/innernet";

#[cfg(not(target_os = "openbsd"))]
pub const DEFAULT_DATA_DIR: &str = "/var/lib/innernet";
#[cfg(target_os = "openbsd")]
pub const DEFAULT_DATA_DIR: &str = "/var/db/innernet";
