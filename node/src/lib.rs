//! The core that every innernet peer runs, whatever its role: what it stores of the other peers
//! of its network, and what it accepts of their announcements.
//!
//! - [`SCHEMA`] is the schema of every node's database, beside which a coordinator keeps its own
//!   tables; [`db`] opens and migrates the database, held with the network of the node as a
//!   [`Store`].
//! - [`store`] reads and writes it, through a [`rusqlite::Connection`], leaving transactions to
//!   the host.
//! - [`accept`] is the input port: every source of announcements hands them to
//!   [`Store::accept`] and gets back what was accepted, or why each was refused.
//! - [`claims`] decides what each peer claims against what is pinned to other keys.
//! - [`snapshot`] is the output: what the node configures, as a snapshot of what it accepted,
//!   which the adapters of [`realize`] realize, the tunnel and the DNS server of [`dns`].
//! - [`runtime`] runs the rounds of a node through its link to the coordinator, on the events of
//!   [`addresses`] and [`events`], with the NAT traversal of [`nat`].

pub mod accept;
pub mod addresses;
pub mod claims;
pub mod db;
pub mod dns;
pub mod events;
pub mod nat;
pub mod realize;
pub mod runtime;
pub mod snapshot;
pub mod store;

pub use db::Store;

/// The schema of every node's database.
pub const SCHEMA: &str = include_str!("schema.sql");

#[cfg(test)]
mod tests;
