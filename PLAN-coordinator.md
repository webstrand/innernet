# Plan: the server as a peer plus a coordinator, and the rewrite of history around it

Status: approved.

## 0. Ground rules (from the operator)
- Every commit must pass `cargo fmt --all -- --check`. That is the only hard rule per commit.
  Clippy and the unit tests should pass at least at the end of each group; a worker may write and
  run its own unit tests.
- No e2e script runs before the end. The e2e scripts (`scripts/e2e-*`, `scripts/test-fetch-pins`)
  run once, at the end; bugs found then are fixed with fixups to the commits that introduced them.
  Network namespaces are available.
- Commits that are defunct are dropped, in particular those whose work a later commit replaced.
  Nothing deployed relies on behaviour added after v2.0.0.
- The hosts file is gone for good: writing it safely is impossible when it is bind-mounted. The DNS
  server that answers the peers' names may land early; forwarding to nameservers lands with
  announcements.
- The workspace crates may be replaced and renamed.
- The early series of simple, upstreamable bug fixes, `origin/main..ee592443c` (24 commits), stays
  as it is. The new commits start after it.

## 1. Target design (agreed)

The branch `coordinator-forward` implements this design, and is the reference end state. Where
this section and the branch differ, the branch wins. The branch also settled the following:
- `node::Store` owns the connection and the network; accepting is a method on it, and no caller
  passes a network. The client's data store wraps a `Store`; the coordinator shares one.
- `Provenance` became the `checked_types` of `Received`; there is no `Authority` and no
  `NodeConfig`.
- Each binary runs on one Tokio runtime. `RestClient` is async; hyper serves the legacy plain-HTTP
  client, and ureq is gone.
- The node loop is driven by events: the coordinator's store-changed signal, the address watcher
  (`node::addresses`, netlink on Linux), the client's fetch interval, and NAT traversal timers.
  NAT traversal (`node::nat`) runs on every node. `address-settle-ms` configures the watcher.
- `TunnelBackend::events()` reports `TunnelEvent`s by polling the device every 10 s. The
  coordinator's observed endpoints follow them; a BPF source may replace the polling later.
- The DNS server runs on the runtime.
- Nothing writes a config after installation. `serve` refuses a config without `quic-port` or
  `bootstrap-endpoint`, or in the flat layout of v2.0.0, and prints what to write. `innernet`
  refuses endpoint overrides keyed by IP, and prints them keyed by public key.
- The backup of a v2.0.0 database is `<interface>.db.v2.0.0`.
- The coordinator sweeps each invitation when it expires, on a timer.
- There is no coordinator mark. The server's own peer is the peer with the key of its config;
  `serve` passes that key to the node and the coordinator, and refuses to start when the database
  holds no such peer. Where section 1 below speaks of a `coordinator` flag, it is void.
- The plain-HTTP API numbers peers, CIDRs and associations by position; no ID is stored.
- The DNS server is authoritative for its zone: the host suffix, or `<interface>.wg` by default.
  An enabled peer's hostname resolves to its address; the apex gets an empty answer; every other
  name in the zone, a disabled peer's included, gets NXDOMAIN; names outside it get REFUSED. An
  empty host suffix is refused. Peer names are unique on every node; an invalid name is NULL.

### Node and coordinator
- One node runtime, in `innernet-node`, runs on every peer: config, data store, snapshot, tunnel
  backend, DNS publisher, own announcement, timer, reload, shutdown. Both binaries run it.
- `innernet` plugs in the poller as its source of updates: fetch `/user/state`, accept, announce
  over the API.
- `innernet-server` plugs in the coordinator, compiled into that binary only. No config key turns
  it off. It runs as another task or thread of the same process: no IPC, and no polling of its own
  coordinator.
- The coordinator is separable by its interface, not used separately. It is started with a private
  key, a database handle, the interface name, the primary IP to serve at, its config (the
  `[coordinator]` table: QUIC port, legacy API), sockets the host has already bound, and hooks.
  - Hooks from the node: observed endpoints, from the node's tunnel; reload, with the new config;
    shutdown.
  - Hooks into the node: a "store changed" notification, which replaces every direct call to
    `reconcile_interface`; and in-process delivery of the node's own announcement.
- The coordinator is the only listener for the API, TLS and legacy alike. It always serves at the
  primary IP of its node, which is the interface address from the config.

### Announcements
- The coordinator applies its own rules first: claim types, assigned ranges, offered name, primary
  IP within the claimed delegation, and that a peer must sign. It then hands the announcement to the
  data store.
- The data store applies the node rules: signature, staleness, network prefix, pins.
- Both run in one transaction, with the coordinator's own writes (reclaim, relayed bytes). If
  either side refuses, the coordinator rolls back and answers the peer with the problem.
- `accept()` loses its `Authority` parameter, and `Authority` moves to the server crate. The node
  accepts the same way on every peer: the coordinator hands over announcements it has vetted, with
  the claim types it checked, exactly like a relayed fetch. `Provenance::Signed` and
  `Provenance::Relayed` may then become one kind.
- The server's node passes the network prefix from its config, as every node does. Today it passes
  `prefix: None`.

### Schema
- One host schema for every node: the same tables for the same data, and annex tables for data
  only the coordinator needs. A column or an index that only the server uses is acceptable when it
  reduces complexity.
  - `peers`: one table. `tls` merges the client's `tls` and the server's `requires_tls`. A
    `coordinator` flag, with a partial unique index, marks the coordinator's peer. `is_redeemed`
    marks invitations.
  - `delegations`: the server's shape (`address` as key, `prefix_len`, `last`, `public_key`,
    `reclaim`).
  - `cidrs`: shared, with an infra mark that replaces "every peer sees the server's own CIDR".
  - Annex tables: `offered_names`, `associations`, `relayed_announcements`.
- Only consistency is enforced in the schema: `CHECK`, `PRIMARY KEY`, `UNIQUE`, and foreign keys
  with `RESTRICT` or `CASCADE`.
  - Every policy trigger moves into code: latches, never-delete, never-change, only-newer, overlap,
    and the unsigned rules.
  - An operator may `sudo sqlite3` and edit the database, deleting dependent rows first.
- The data store reads SQLite directly. There is no in-memory index (`Records`, `PeersIndex`, the
  HashMaps in `accept::decide`). Pin checks use SQLite indexes.

### Peers and invitations
- Invitations are ordinary peers of the node, marked by `is_redeemed`. They are pinned and
  configured on the tunnel like any peer, and the coordinator never relays them.
  - On redemption, the coordinator deletes the invitation's peer, with its announcement and pins,
    and inserts the redeemed peer, in one transaction.
  - The sweeper deletes expired invitations the same way.
- The coordinator may delete any peer. Deleting a peer that never announced is free. A peer that
  has announced may be deleted, but its resources must be treated as gone for good, since clients
  keep its pins.
- The coordinator relays its flagged peer to every peer, and refuses to withdraw the delegation
  that holds its primary IP.

### Binaries and config
- Every `innernet-server` admin subcommand is an admin client of the running coordinator over TLS,
  using the server's key, connecting to the primary IP and QUIC port from the config.
  - It fails when `serve` isn't running, since the interface is then unmanaged.
  - `new` and `uninstall` stay local.
- `innernet-server` checks at start, from its config alone, that the interface address lies within
  its configured `allowed-ips`, or within its delegation when that key is unset, and exits
  otherwise. This check belongs to the binary's start-up code, not to the coordinator.
- The server's config is the client's interface config, minus the `[server]` table, plus a
  `[coordinator]` table and an explicit bootstrap external endpoint.
  - A v2.0.0 server config must still load; new keys get serde defaults.
  - The bootstrap endpoint defaults to the endpoint recorded for the server's peer at init.
- The server's own announcement is built by the client's `own_announcement`, and re-announced on
  the runtime's timer like any node's.
- Compatibility: only v2.0.0 has users. The server database from v2.0.0 migrates through the
  existing `db::rebuild`, which writes the merged schema. The client's JSON store from v2.0.0
  imports through `import_legacy`. Nothing added after v2.0.0 needs a migration.

## 2. Method

Two phases, so that the rewritten history has a verified end state to converge on.

### Phase 1: forward refactor (one fork, in a worktree)
- Branch `coordinator-forward`, made from `locus-non-rampant`, in its own worktree.
- The design above is implemented as a few commits atop HEAD.
- Each commit passes `cargo fmt --all -- --check`. The tip passes
  `cargo clippy --workspace --all-targets --offline -- -D warnings` and
  `cargo test --workspace --offline`. No e2e script runs.
- The tip's tree is the **reference end state** for phase 2.

### Phase 2: the rewrite of history (clean workers, one group at a time)
- A backup ref `backup/locus-non-rampant-2026-10-21` is created first.
- The new series is built on branch `locus-rewrite`, in its own worktree, atop `ee592443c`, the
  end of the early bug fixes. Nothing before it is touched.
- Its first commits are the `WIP TODO:` notes (2abe9ecc0, with the `CLAUDE.md` fixup squashed),
  and this plan, cherry-picked back, so that every worker reads them.
- `locus-non-rampant` is reset to the new tip only after approval.
- The groups in section 3 are worked in order. A clean worker per group gets this file, the group's
  list of original commits, and the path of the reference tree. Each worker:
  1. cherry-picks or rewrites each commit so that it reads as written for the new architecture:
     subjects kept where they still fit, bodies adjusted, scripts and README changes folded into
     their feature;
  2. checks every commit with `cargo fmt`, and the group's end with clippy and the tests;
  3. reports a summary of each commit and the remaining diff to the reference tree.
- **Invariant:** after the last group, `git diff locus-rewrite coordinator-forward` is empty, or
  holds only reviewed, intentional differences, apart from this plan and the notes.
- Worktrees live under `/home/auth/innernet/.worktrees/`; anything outside the project root is
  on tmpfs.
- `WIP PRIVATE:` commits are never dropped. `fixup!` commits squash into their targets.
  `WIP TODO:` commits stay; the uncommitted line in `CLAUDE.md` is folded into 2abe9ecc0.

## 3. The new series (groups, with original commits)

Order within a group follows the original unless noted. P = WIP PRIVATE.

### Kept as is: the early bug fixes
`origin/main..ee592443c`, 24 commits, among them the client's SQLite store (f23834c60) and the
server's reconciliation (981e7ecc5). G1 transforms what they built.

### G0: notes and groundwork, independent of the architecture (cherry-picked)
2abe9ecc0 (WIP TODO, with the `CLAUDE.md` fixup), the plan (WIP TODO), 02d8f9956, 8e5624157,
071f2d2f9, 9a29d6b6f, 4c0b813f2, 60d09a719, 8ceb6e510 + 86d2a9e9c (names), 9399131e4 (Prefix),
fb74f76eb (CBOR module), 55140ce56, 4f07bb317, b3b395d8b P, 0587ceb5c P, 38e1b60d8 P,
ebce5f6ad + e3b9f85a2 P

### G1: the architecture, early (new commits, transforming what the early fixes built)
1. **node: a crate with the host schema and a store that reads SQLite directly.** It holds
   `peers`, `endpoints`, `cidrs` and `prefix_pins`, enforces only consistency in the schema, and
   puts policy in code. The client's data store moves onto it, and its triggers and in-memory
   index (f23834c60, bee41e26a, 981992183) go. From: c05cada6a (store part).
2. **node: the snapshot and the tunnel backend; the client configures its interface from them.**
   From: fe7b1270c, 0d021132e.
3. **server: the database is the node schema plus annex tables, keyed by public key.** It
   synthesizes IDs for the legacy API and migrates v2.0.0 through `rebuild`. From: aba27c566 (moved
   early).
4. **server: flag the coordinator's peer, and find it by the flag.** It replaces the lookups by
   key of e86eb9374 and fa7db9300.
5. **server: run the node runtime with the coordinator as a service.** `Coordinator::spawn`, the
   store-changed notification in place of 981e7ecc5's direct reconciliation, and invitations as
   `is_redeemed` peers of the node, with the expiry timer. The loop is event-driven from the
   start: the address watcher, NAT traversal in the node, and tunnel events, on one Tokio runtime
   per binary.
6. **Stop writing the hosts file, and answer the peers' names in a DNS server run by the node
   runtime.** From: 07579b531, afdcaa230 and 71664f9fc (the answering part). The hosts-file
   commits after ee592443c are dropped. The removal may land before the DNS server; a stretch
   without name resolution is acceptable.

Commit e0cfffc6e of the reference branch shows that two Linux-only files
(`shared/src/netlink.rs`, `wireguard-control/src/backends/kernel.rs`) went unformatted; the
rewrite formats each change in the commit that makes it.

The start-up check lands in G9, once `allowed-ips` exists. The infra mark lands in G6, once CIDRs
are keyed by prefix; until then it is a column on the CIDR row.

### G2: TLS
26cd64292 (the listener belongs to the coordinator; the latch is the shared `tls` column),
5fbb9cb01, c538058f0 (merges into the shared `tls` column, no trigger), 57112f09a, 94564663b,
5dab27c6b, 13b909093, df060bd9f, f9aefb8bb, and the two commits that G0 deferred: 9a29d6b6f
and 8e5624157. G1 already made `RestClient` async on hyper.

### G3: the admin API by key, and the server's admin CLI over TLS
be4f3e796 + 150fb9f84 + 5fa6666b3 (squashed: tags are a hash of the state from the start),
9b6d5f85c, e8afdd737, 536c74183, 6a3aa57d2, and a **new commit: `innernet-server` admin
subcommands as TLS clients of the running coordinator.**

### G4: transfers without IDs, optional names, client options
edbdfd583, 72ac47a9d, 5ecef8969, 75169e6a3, 6048864d6. 99f73cf27 is dropped: the runtime of G1
already retries failed fetches.

### G5: delegations
a7a56ffc5 (the shared `delegations` table; no triggers), e2dd42701 (pins checked through indexes;
no `PeersIndex`), 7f98a4db1, 5e79a7c7b, add7ed75b (API part only; the CLI part goes through TLS),
df612ef44, c2d8724bc, e8d206df6, 9bb95a16c, 5bb6b6d6c

### G6: CIDRs and associations by prefix
a2acac7a0, b788f048e, cb3a4c370, 59bfa3f2c. G1 already keys CIDRs and associations by prefix in
the server's database, with the infra mark; what remains is the API by prefix.

### G7: CBOR and problem details
b8ec1cd6b, acdb73aa9, 81deee9a4, e41c0902c (its script part folded away, since 063c98d5c replaces
it), f8775b683. The `PeerContents` CBOR test that G0 cut from fb74f76eb comes back here.

### G8: QUIC
10ea1f28a, 5bbbcc994, eab436342, 3526d1f8d, 216408ecc (`quic_port` stays on the shared `peers`
table), 2aad90c78 (the coordinator gets its sockets from the binary), 1795e1a9e, 7f02f82cb,
cad4c74ee, 063c98d5c, 591f01c08, f4fe4fd98, 4cbdde025

### G9: announcements (3cc24fd97 split and rewritten; the node-core commits absorbed)
1. shared: signed announcements (`shared/announcement.rs`)
2. node: accept announcements under the node rules, in code over SQLite, without an authority.
   From: c05cada6a (accept, claims), 8608b160e, 0942ad526 (node part).
3. server: the coordinator checks claims, then hands announcements to its node, with annex tables
   (`relayed_announcements`, `offered_names`, `reclaim`). From: 3cc24fd97, 0942ad526.
4. client: announce, and accept relayed announcements
5. node: sign and build the node's own announcement alike on every node; the server uses the
   client's builder. From: f9ad9d573, 94b359c24, e35aa488d + b0a17f9f6.
6. server: check at start, from config, that the primary IP lies within the allowed IPs (new)
7. f1d7647e0, 147c9f4ef

### G10: config, nameservers, forwarding
1. e264bf825 (the server's config gains the interface options, `[coordinator]` and the bootstrap
   endpoint; nothing writes a config after installation, and the shims for the layouts of v2.0.0
   are replaced by refusals that print what to write)
2. 7dd8c88d2, a267c0024
3. cab86a22c, with the forwarding parts of afdcaa230 and 71664f9fc: the DNS server of G1.6
   forwards to the nameservers that peers offer
4. 132890a49, 21346c3da, 59d2210a9 P (dotted names; no hosts part)

### G11: tail
a2950b05d, e83097046 P + dcc7c42bb (test-fetch-pins against the merged schema), 9ad1d5ab5 +
7b57e2664 (README rewritten for the final design), 4540e879c (dissolved into its sources)

## 3a. Comments
Every commit that a worker writes or rewrites trims its comments of these faults:
- Thoughts, plans or history in code: "now", "previously", "this version", "as discussed".
  "origin" names a git remote, not a release: use "clients that predate TLS", "a pre-TLS
  invitation", "v2.0.0".
- A comment that restates the code: a doc that turns the signature into a sentence ("What
  changed.", "The prefixes of `cidrs`."), or a test comment that narrates the next assert.
- A run-on doc of chained clauses ("as X makes it, as Y tells"). Split it, or cut it to the rule
  that matters; list the rules where there are several.
- The same rationale in several places. It is stated once, where it is enforced, and linked from
  elsewhere: pinning in the node's accept, the coordinator being an ordinary peer in one place
  in the client.
- Docs stacked from two edits, docs on the wrong item, and lines broken mid-sentence.
- The rationale for a removed feature, such as the hosts file, belongs in the commit message.

Comments that state why stay: invariants, security or protocol rationale, and non-obvious
constraints.

## 4. Dropped or dissolved
- Obsoleted by the removal of the hosts file: 7258e0764, fb1f91253, 994b05cea, 5fe327b38. The
  hosts-file commit in the early fixes, 27e964bc8, stays, as do the JSON-store fixes bf453feb5 and
  4999ed0f3: upstream still has both.
- Absorbed: 8608b160e's copies of the tables, e41c0902c's probe, 4540e879c, and whatever a later
  commit replaced.

## 5. Risks
- The scripts that edit the server database by hand (e2e-tls-auth, e2e-announcements,
  test-fetch-pins) break on each schema change, and must follow it in every group.
- Cherry-picking out of order (G0) conflicts in `shared/lib.rs` and `shared/types.rs`.
- The e2e scripts run only at the end, so behavioural bugs surface late, and are sent back as
  fixups to the commits that introduced them.
