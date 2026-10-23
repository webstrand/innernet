# innernet

[![Actively Maintained](https://img.shields.io/badge/Maintenance%20Level-Actively%20Maintained-green.svg)](https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d)
[![MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/tonarino/innernet/blob/master/LICENSE)

A private network system that uses [WireGuard](https://wireguard.com) under the hood. See the [announcement blog post](https://blog.tonari.no/introducing-innernet) for a longer-winded explanation.

<img src="https://user-images.githubusercontent.com/373823/118917068-09ae7700-b96b-11eb-80f4-6860072d504d.gif" width="600" height="370">

`innernet` is similar in its goals to Slack's [nebula](https://github.com/slackhq/nebula) or [Tailscale](https://tailscale.com/), but takes a bit of a different approach. It aims to take advantage of existing networking concepts like CIDRs and the security properties of WireGuard to turn your computer's basic IP networking into more powerful ACL primitives.

`innernet` is not an official WireGuard project, and WireGuard is a registered trademark of Jason A. Donenfeld.

This has not received an independent security audit, and should be considered experimental software at this early point in its lifetime.

## Usage

### Server Creation

Every `innernet` network needs a coordination server to manage peers and provide endpoint information so peers can directly connect to each other. Create a new one with

```sh
sudo innernet-server new
```

The init wizard will ask you questions about your network and give you some reasonable defaults. It's good to familiarize yourself with [network CIDRs](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing) as a lot of innernet's access control is based upon them. As an example, let's say the root CIDR for this network is `10.60.0.0/16`. Server initialization creates a special "infra" CIDR which contains the `innernet` server itself and is reachable from all CIDRs on the network.

The server must run before it can change the network: every admin subcommand of `innernet-server`, such as `add-cidr` and `add-peer`, goes through the API of the running server, as the admin subcommands of `innernet` do. Run it with `innernet-server serve <interface>`, or on Linux via `systemctl`, with `systemctl enable --now innernet-server@<interface>`. On a home network, port forwarding to the `Listen Port` given at creation lets peers reach the server.

Next we'll also create a `humans` CIDR where we can start adding some peers.

```sh
sudo innernet-server add-cidr <interface>
```

For the parent CIDR, you can simply choose your network's root CIDR. The name will be `humans`, and the CIDR will be `10.60.64.0/24` (not a great example unless you only want to support 256 humans, but it works for now...).

By default, peers which exist in this new CIDR will only be able to contact peers in the same CIDR, and the special "infra" CIDR which was created when the server was initialized.

A typical workflow for creating a new network is to create an admin peer from the `innernet-server` CLI, and then continue using that admin peer via the `innernet` client CLI to add any further peers or network CIDRs.

```sh
sudo innernet-server add-peer <interface>
```

Select the `humans` CIDR, and the CLI will automatically suggest the next available IP address (`--delegation <subnet>` gives the peer a subnet instead, as [Delegations](#delegations) describes). Any name is fine, just answer "yes" when asked if you would like to make the peer an admin. The process of adding a peer results in an invitation file. This file contains just enough information for the new peer to contact the `innernet` server and redeem its invitation. It should be transferred securely to the new peer, and it can only be used once to initialize the peer.

### Peer Initialization

Let's assume the invitation file generated in the steps above have been transferred to the machine a network admin will be using.

You can initialize the client with

```sh
sudo innernet install /path/to/invitation.toml
```

You can customize the network name if you want to, or leave it at the default. `innernet` will then connect to the `innernet` server via WireGuard, generate a new key pair, and register that pair with the server. The private key in the invitation file can no longer be used.

If everything was successful, the new peer is on the network. You can run things like

```sh
sudo innernet list
```

or

```sh
sudo innernet list --tree
```

to view the current network and all CIDRs visible to this peer.

Since we created an admin peer, we can also add new peers and CIDRs from this peer via `innernet` instead of having to always run commands on the server.

### Adding Associations between CIDRs

In order for peers from one CIDR to be able to contact peers in another CIDR, those two CIDRs must be "associated" with each other.

With the admin peer we created above, let's add a new CIDR for some theoretical CI servers we have.

```sh
sudo innernet add-cidr <interface>
```

The name is `ci-servers` and the CIDR is `10.60.64.0/24`, but for this example it can be anything.

For now, we want peers in the `humans` CIDR to be able to access peers in the `ci-servers` CIDR.

```sh
sudo innernet add-association <interface>
```

The CLI will ask you to select the two CIDRs you want to associate. That's all it takes to allow peers in two different CIDRs to communicate!

You can verify the association with

```sh
sudo innernet list-associations <interface>
```

and associations can be deleted with

```sh
sudo innernet delete-associations <interface>
```

### Enabling/Disabling Peers

Peers cannot be deleted, but an admin can disable them. Other peers route nothing to a disabled peer, and its name resolves to no address. A disabled peer keeps its delegations, and a client that has seen its announcement refuses its addresses and its name to every other peer.

Disable a peer with

```su
sudo innernet disable-peer <interface>
```

Or re-enable a peer with

```su
sudo innernet enable-peer <interface>
```

### Delegations

An admin can delegate multiple subnets of a peer's CIDR, such as `10.60.64.16/28`, to the peer, allowing it to receive traffic on multiple IPs visible to other peers in its CIDR and associated CIDRs.

An admin client or the server adds, withdraws or reclaims a delegation with

```sh
sudo innernet add-delegation <interface> --name <peer> --prefix <subnet>
sudo innernet withdraw-delegation <interface> --name <peer> --prefix <subnet>
sudo innernet reclaim-delegation <interface> --name <peer> --prefix <subnet>
```

or the same subcommands of `innernet-server`. The client subcommands require a server that speaks TLS. The server refuses to withdraw a delegation that the peer still announces. `reclaim-delegation` marks the delegation instead, and the server withdraws it once the peer no longer announces it.

A client announces all of its delegations by default. The `[interface]` section of its config restricts what it announces and what other peers route to it:

```toml
[interface]
delegation = ["10.60.64.2/32", "10.60.64.16/28"]  # the subnets that the client announces
allowed-ips = ["10.60.64.2/32", "10.60.64.16/29"] # the subnets that other peers route to the client
extra-addresses = ["10.60.64.17"]                 # addresses that the client assigns to its interface besides `address`
```

### DNS

Each node can run a DNS server that resolves the names of the enabled peers, such as `<peer>.<interface>.wg`. The DNS server is authoritative for the zone of these names, `<interface>.wg`, or the suffix that `--host-suffix` gives, which can't be empty: a name in the zone that no enabled peer has, such as that of a disabled peer, doesn't exist (NXDOMAIN), and a name outside the zone is refused. innernet writes no hosts file, so the names of the peers resolve only through a DNS server. A `[dns]` table in the config enables the DNS server, in `/etc/innernet/<interface>.conf` on a client running `innernet up --daemon`, and in `/etc/innernet-server/<interface>.conf` on the server:

```toml
[dns]
listen = "127.0.0.55:53"
```

The listen address should be a loopback address with a port below 1024. The operator must point the system resolver at it. With systemd-resolved 258 or later, a file such as `/etc/systemd/dns-delegate.d/innernet.dns-delegate` does so, once the operator runs `systemctl reload systemd-resolved`:

```ini
[Delegate]
DNS=127.0.0.55:53
Domains=~<interface>.wg
```

With dnsmasq, the line `server=/<interface>.wg/127.0.0.55` does so.

A peer can offer a nameserver, at an address within its delegations, for its own name and the names under it, such as `www.<peer>.<interface>.wg`:

```toml
[interface]
announce-nameserver = "10.60.64.18:53"
announce-zone = "example.com" # optional: the nameserver answers for example.com in place of <peer>.<interface>.wg
```

The DNS server of another node forwards queries to the nameserver only if the `forward` key of its `[dns]` table selects the peer; by default it forwards to no peer, and answers for the peer's name itself. The key lists selectors: `"*"` selects every peer, a peer's name selects that peer, and a peer's name after `!` excludes that peer, whatever else selects it. A list of exclusions alone selects no peer. The DNS server never forwards to a disabled peer, sends a nameserver queries for the names of its peer only, and drops answers that point outside the peer's delegations.

```toml
[dns]
listen = "127.0.0.55:53"
forward = ["*", "!c"] # forwards to the nameserver of every peer but c
```

### What Wakes a Node

A node configures its interface in rounds: it brings what it holds of the network up to date, configures its tunnel and its DNS server, announces itself, and starts NAT traversal of the peers that changed, whose steps follow five seconds apart. `innernet up --daemon` runs a round of each interface at its `--interval` and whenever the host's addresses change; the server runs one whenever its coordinator changes the network and whenever the host's addresses change. On Linux, the kernel reports changes of the addresses as they happen. The node reads its tunnel every ten seconds for the endpoints at which it reaches its peers and the handshakes that complete: the server reports to each peer the endpoints at which its tunnel reaches the others, and the NAT traversal of a peer ends once a handshake with it completes, which each step of the traversal also checks.

### Editing the Config

The client writes `/etc/innernet/<interface>.conf` only when it installs the interface. The operator edits it by hand, and every fetch reads and applies it.

```toml
[interface]
listen-port = 51820                     # the WireGuard listen port; random if unset
external-endpoint = "203.0.113.7:51820" # the endpoint at which other peers reach this one, when the
                                        # endpoint that the server observes doesn't work; a host of
                                        # 0.0.0.0 keeps the observed host
address-settle-ms = 200                 # how long the node waits, once the host's addresses
                                        # change, before it runs a round; 200 if unset

[peer-endpoint-overrides]
"<public key of the peer>" = "192.168.1.20:51820" # the endpoint at which this client reaches the peer
```

### The Server's Config

The server is a peer like any other, beside which runs the coordinator of the network. Its config, `/etc/innernet-server/<interface>.conf`, describes its peer in an `[interface]` table with the keys of a client's, and the coordinator in a `[coordinator]` table:

```toml
[interface]
network-name = "<interface>"
address = "10.60.0.1/16"   # the server's primary IP, at which the coordinator serves its API
private-key = "..."
listen-port = 51820
# Any other key of a client's [interface] table: delegation, allowed-ips, extra-addresses,
# external-endpoint, announce-nameserver, announce-zone, address-settle-ms.

[coordinator]
quic-port = 51821                         # the UDP port of the API, over QUIC
bootstrap-endpoint = "203.0.113.1:51820"  # the endpoint that invitations name
legacy-api = true                         # whether the API is also served in plain HTTP
```

Peers reach the API at the server's primary IP through the allowed IPs that the server's peer announces, so the server refuses to start if its primary IP lies outside the `allowed-ips` of its config, or, when the config states none, outside its `delegation`. The server's peer announces the bootstrap endpoint as its endpoint unless `external-endpoint` states another; once peers know the server, they reach it where it announces.

Nothing writes the config after `innernet-server new`. The server refuses to start on a config that lacks `quic-port` or `bootstrap-endpoint`, and on the config of innernet-server 2.0.0, whose keys lie at the top level; it then prints the config with what it lacks, in this layout, which the operator writes in its place. Likewise, `innernet` refuses a `[peer-endpoint-overrides]` table keyed by peer IP, and prints each override keyed by the peer's public key.

### Repairing the Database

Each node's database, `/var/lib/innernet/<interface>.db` on a client and `/var/lib/innernet-server/<interface>.db` on the server, enforces only its consistency: types, keys and references. What a node accepts, such as which announcement replaces another and what stays pinned to a key, is decided by innernet. An operator who must repair a database edits it with `sqlite3`, while innernet isn't running, and deletes the rows that refer to a row before the row itself. On its first start on the database of innernet-server 2.0.0, the server copies the database, before it rebuilds it, to `<interface>.db.v2.0.0`, or `<interface>.db.v2.0.0.N` if that exists, which innernet-server 2.0.0 can open again.

### Remove Network

To permanently uninstall a created network, use

```sh
sudo innernet-server uninstall <interface>
```

Use with care!

### Limitations

- Moving the server's internal address leaves the clients unable to reach it; the operator must update each client by hand.
- The API runs over QUIC, which needs an interface MTU of at least 1228 on an IPv4 network, or 1248 on IPv6. The default MTU, 1280, suffices.

## Security recommendations

If you're running a service on innernet, there are some important security considerations.

### Enable strict Reverse Path Filtering ([RFC 3704](https://tools.ietf.org/html/rfc3704))

Strict RPF prevents packets from _other_ interfaces from having internal source IP addresses. This is _not_ the default on Linux, even though it is the right choice for 99.99% of situations. You can enable it by adding the following to a `/etc/sysctl.d/60-network-security.conf`:

```
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Also apply to interfaces that exist at the time this sysctl is applied, as they might have been
# created with value 2 (loose), which takes precedence even when all.rp_filter is 1.
# Note that using the * match does not apply to the special `all` and `default` knobs.
net.ipv4.conf.*.rp_filter = 1
```

### Bind to the WireGuard device

If possible, to _ensure_ that packets are only ever transmitted over the WireGuard interface, it's recommended that you use `SO_BINDTODEVICE` on Linux or `IP_BOUND_IF` on macOS/BSDs. If you have strict reverse path filtering, though, this is less of a concern.

### IP addresses alone often aren't enough authentication

Even following all the above precautions, rogue applications on a peer's machines could be able to make requests on their behalf unless you add extra layers of authentication to mitigate this CSRF-type vector.

It's recommended that you carefully consider this possibility before deciding that the source IP is sufficient for your authentication needs on a service.

### Signed announcements

Each peer signs what it claims, its delegation and its name, and the endpoints at which it is reached. Once a client has seen a peer's signed announcement, the server can no longer give that peer's addresses or name to another key. A client that hasn't seen it yet trusts what the server reports.

### TLS

The API runs over HTTP/3 over QUIC, at the server's primary IP and the `quic-port` of its config, inside the WireGuard tunnel. A client and the server authenticate each other in TLS by their WireGuard keys, and each pins the key of the other, so no certificate authority takes part. A peer presents its key as a raw public key (RFC 7250). The server presents its key in a self-signed certificate, so that tools that know no raw public keys, such as curl with `--pinnedpubkey`, can reach it.

The server latches each peer to TLS: every peer that it invites, and a peer redeemed by a client that predates TLS once that peer first connects over TLS. The server then refuses that peer over plain HTTP, and makes no peer an admin before the latch.

### Turn off the legacy API

The server serves clients that predate TLS over plain HTTP, which identifies a client by its source address alone. Once every client speaks TLS, `legacy-api = false` in the server's config turns it off.

## Installation

`innernet` has only been officially tested on Linux and macOS. Experimental OpenBSD support has been added recently. Feedback from early testers is most welcome. Please report any issues you may encounter.
We hope to support more platforms in the future.

### Runtime Dependencies

It's assumed that WireGuard is present on your system, either via kernel support (`Linux 5.6` and later or `OpenBSD 6.8` and later) or by installing the [`wireguard-go`](https://git.zx2c4.com/wireguard-go/about/) userspace implementation.

[WireGuard Installation Instructions](https://www.wireguard.com/install/)

### Arch Linux

```sh
pacman -S innernet
```

### Debian and Ubuntu

[**@tommie**](https://github.com/tommie) is kindly providing Debian/Ubuntu innernet builds in the https://github.com/tommie/innernet-debian repository.

### Other Linux Distributions

We're looking for volunteers who are able to set up external builds for popular distributions. Please see issue [#203](https://github.com/tonarino/innernet/issues/203).

### macOS

```sh
brew install tonarino/innernet/innernet
```

### Cargo

```sh
# to install the latest released innernet:
cargo install --locked innernet

# to install the latest released innernet-server:
cargo install --locked innernet-server
```

Note that you'll be responsible for updating manually or through tools like [`cargo-update`](https://crates.io/crates/cargo-update).
You can omit `--locked` to use newer (but compatible) dependency versions, losing determinism and testing by our CI.

## Development

### `innernet-server` Build dependencies

- `rustc` / `cargo` (version 1.50.0 or higher)
- `libsqlite3`

Build:

```sh
cargo build --release --bin innernet-server
```

The resulting binary will be located at `./target/release/innernet-server`

### `innernet` Client CLI Build dependencies

- `rustc` / `cargo` (version 1.50.0 or higher)

Build:

```sh
cargo build --release --bin innernet
```

The resulting binary will be located at `./target/release/innernet`

### Testing

The scripts `scripts/e2e-network`, `scripts/e2e-tls-auth`, `scripts/e2e-announcements` and `scripts/e2e-dns` run end-to-end tests unprivileged, in network namespaces. `e2e-network` covers a network's life cycle: an admin client that builds the network out, CIDRs renamed from either side, invitations that expire, peers that redeem their invitations at once, and traffic between peers of associated CIDRs. The scripts need user namespaces and the kernel WireGuard module; `e2e-dns` also needs dnsmasq and dig. Each builds the workspace's binaries, and `--keep` keeps its work directory, with the configs, data stores and logs.

```
scripts/e2e-network [--keep]
```

A new feature should come with a test case in one of these scripts.

### Releases

Please run the release script from a Linux machine: generated shell completions depend on available wireguard backends and Mac doesn't support the `kernel` backend. 

1. Ensure you have the release script dependencies `help2man` and `cargo-release` installed.
1. Create a new branch on top of fresh `main`.
1. Run `./release.sh [patch|major|minor|rc]` and submit its results as a PR.
1. Once the PR is merged, switch to `main` that contains it.
1. Publish to crates.io using `cargo release publish` (pass `--execute` after a dry run).
1. Tag the commit using `git tag -f -a v<version> -m "release v<version>`.
1. Push the created tag to the repo using `git push origin v<version>`.
1. Create a GitHub release from the tag, generate release notes and highlight important changes.
1. Bump the [homebrew-innernet](https://github.com/tonarino/homebrew-innernet) formula version.
