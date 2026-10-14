# TODO

## Security

- [ ] **Peer names are not pinned.** The data store pins each public key to its IP, but not to
  its name, so the coordinator can rename peers at will. A rename takes effect in the hosts file
  on the next fetch, so the coordinator can point a trusted name at another peer's IP.
- [ ] **A data store that conflicts with the introduction is kept.** When the data store already
  holds another public key at the coordinator's IP, or the client's own, `DataStore::introduce`
  only logs a warning and keeps the stored peer. A data store that was poisoned before the
  introduction records existed therefore stays poisoned. The interface config should win.

## Robustness

- [ ] **Daemon exits on any fetch error.** `up` propagates errors from `fetch` with `?`, so
  `innernet up --daemon` exits and stops every other interface it manages, including on
  transient errors from `report_candidates` and `NatTraverse::step`, and on a server that
  predates TLS. Log the error and retry on the next interval instead.
- [ ] **Non-atomic writes.** `DataStore::write` truncates and then writes in place, and so does
  `InterfaceConfig::save` (`File::create`). A crash in between leaves an empty file: an empty
  data store opens as a new one, which silently discards every pin, withdrawn delegations
  included, despite the refusal of a data store that fails to parse, and an empty config loses
  the private key. Write to a temporary file and rename it over the original.
- [ ] **Hosts file writer.** `HostsBuilder::write_to` panics on a line of `/etc/hosts` that is
  not valid UTF-8 (`line.unwrap()`), and reopens the file by path between reading it and
  replacing it (`fs::copy`, `write_clobber`, `rename`).
- [ ] **`show` skips an unreadable data directory.** `show` treats an interface as managed by
  innernet if `DataStore::get_path(..).exists()`, which returns false when the data directory
  cannot be read, so the interface is skipped without an error. `try_exists()` would report the
  error instead.
- [ ] **A conflicting coordinator entry cuts the tunnel.** A fetched peer that conflicts with the
  pin of the coordinator is dropped, and the coordinator, absent from the update, is disabled
  and removed from the interface. The client can then no longer reach the coordinator to fetch
  again. The coordinator should remain configured from the interface config whatever a fetch
  reports.
- [ ] **`delete-peer` suggests a command that fails for a nameless peer.** Its message tells the
  operator to run `innernet forget-peer <interface> --name <name>`, and prints `[unnamed]` as the
  name of a peer without a name.
- [ ] **Unused dependency.** `client-core` depends on `regex` but does not use it.

## Announcements

- [ ] **Announcements travel by polling.** A peer's announcement reaches the other peers only on
  their next fetch, so a narrowed delegation keeps being routed to it until then. With TLS
  tunnels to every peer, the coordinator could push announcements to peers as it receives them.
- [ ] **Hosts entries of peers that offer a nameserver.** A peer whose nameserver is accepted
  has no hosts file entry, so its name resolves only through a client's DNS forwarder, and not
  at all on a client without one. The announcement could carry a hosts entry that clients write
  regardless.
- [ ] **Forwarded DNS answers are not authenticated.** The announcement authenticates where a
  peer's nameserver is, but not what it answers, and a nameserver beyond the tunnel can be
  spoofed. The announcement could carry an Ed25519 DNSSEC key, separate from the WireGuard key so
  that the nameserver's configuration never holds the WireGuard private key, as the trust anchor
  of the zone, and the forwarder could validate answers against it.

## Upstream

- [ ] **Public API changes.** The pull request description should list the changed public
  signatures, since they break external users of the crates:
  - `innernet-client-core`: `DataStore::open` and `DataStore::open_or_create` take the interface
    config, and `DataStore::update` replaces `DataStore::update_peers_and_set_cidrs`.
  - `innernet-shared`: `DeviceExt::diff` and `PeerDiff::new` take endpoint overrides, and the
    WIP PRIVATE commit changes `warn_on_dangerous_mode` and `InterfaceConfig::from_file` to take
    an open file. `PeerContents::name` is an `Option<Hostname>`, `PeerContents` gains the
    `announcement` and `observed_endpoint` fields, and `prompts::rename_peer` returns the ID of
    the peer rather than its old name.
  - The new crate `innernet-domain` validates peer names, and the server database gains the
    migrations 3 (nullable peer names) and 4 (announcements).
- [ ] **Compatibility.** A client without the commit that allows peers without a name fails to
  deserialize a state that holds one, and so fails to fetch from a server that holds one. A
  client that speaks TLS refuses a server that predates it, so the release notes must tell
  operators to upgrade the server before its clients.
- [ ] **WIP PRIVATE overlap.** The commit that adds signed endpoint announcements adds
  `serde_json` to the `[dev-dependencies]` table of `shared`, which the WIP PRIVATE commit for
  the `test-util` feature introduces. Dropping that WIP PRIVATE commit conflicts there.
