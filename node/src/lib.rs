//! The core that every innernet peer runs, whatever its role: what it stores of the other peers
//! of its network, and what it accepts of their records.
//!
//! - [`SCHEMA`] is the schema of every node's database, beside which a coordinator keeps its own
//!   tables; [`db`] opens and migrates the database, held with the network of the node as a
//!   [`Store`].
//! - [`store`] reads and writes it, through a [`rusqlite::Connection`], leaving transactions to
//!   the host.
//! - [`accept`] is the input port: every source of the records of peers hands them to
//!   [`Store::accept`] and gets back what was accepted, or why each was refused.
//! - [`snapshot`] is the output: what the node configures, as a snapshot of what it recorded,
//!   which the adapters of [`realize`] realize.

pub mod accept;
pub mod db;
pub mod realize;
pub mod snapshot;
pub mod store;

pub use db::Store;

/// The schema of every node's database.
pub const SCHEMA: &str = include_str!("schema.sql");

#[cfg(test)]
mod tests;
