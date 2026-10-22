-- Version 1 of the schema of a node's database: what every node stores of the peers of its
-- network, whatever its role. A coordinator adds tables of its own, its annex, beside these, and
-- may use columns that other nodes leave at their defaults. Public keys are their 32 raw bytes,
-- and addresses their 4 (IPv4) or 16 (IPv6) bytes in network order.
--
-- The schema holds what keeps the database consistent: types, checks, keys and references. What
-- a node accepts and keeps, such as which announcement replaces another and what stays pinned to
-- a key, is decided by the node's code, so that an operator who must repair a database can edit it
-- with `sqlite3`, deleting the rows that refer to a row before the row itself.

PRAGMA application_id = 1768844914; -- "innr"

CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value ANY
) STRICT, WITHOUT ROWID;

-- The lowest version of the schema that a binary must know to open the database. A migration
-- raises it only if a binary that doesn't know the migration would break an invariant it adds.
INSERT INTO meta VALUES ('min_reader_version', 1);

-- The peers of the network, invitations not yet redeemed included, as the node records them.
CREATE TABLE peers (
  public_key                    BLOB PRIMARY KEY CHECK (length(public_key) = 32),
  -- The name that the peer claims, pinned to its key, or NULL for a peer that claims none.
  name                          TEXT,
  is_admin                      INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
  is_disabled                   INTEGER NOT NULL DEFAULT 0 CHECK (is_disabled IN (0, 1)),
  -- Whether the peer is redeemed; a peer that isn't is an invitation.
  is_redeemed                   INTEGER NOT NULL DEFAULT 1 CHECK (is_redeemed IN (0, 1)),
  invite_expires                INTEGER, -- UNIX time in seconds
  persistent_keepalive_interval INTEGER CHECK (persistent_keepalive_interval BETWEEN 0 AND 65535),
  -- Whether the peer speaks TLS, which the node sets on authenticated evidence and never clears:
  -- a client never falls back to plain HTTP with a coordinator that has answered over TLS, and a
  -- coordinator never again identifies a peer that has authenticated over TLS by its address.
  tls                           INTEGER NOT NULL DEFAULT 0 CHECK (tls IN (0, 1)),
  -- The UDP port of the TLS API of the coordinator's peer, which runs over QUIC at its primary IP,
  -- or NULL while it is unknown or for any other peer.
  quic_port                     INTEGER CHECK (quic_port BETWEEN 1 AND 65535),
  -- Whether the peer has signed an announcement that the node accepted, after which the node
  -- accepts only its signed announcements.
  announces                     INTEGER NOT NULL DEFAULT 0 CHECK (announces IN (0, 1))
) STRICT, WITHOUT ROWID;

-- No name is pinned to two keys.
CREATE UNIQUE INDEX names_pinned_once ON peers (name);

-- The ranges that the coordinator assigns the peers: aligned prefixes, of which each peer claims
-- its delegation in its announcements. A lone address is a /32 or /128 range. `address` is the
-- first address of the prefix, whose host bits are zero, and `last` its last address, so that the
-- range of an address, and ranges that overlap, are found by comparing addresses of the same
-- length. A coordinator marks a range `reclaim` when it stops being assigned once the peer, having
-- claimed some of it, announces without claiming any of it. A client records the ranges that the
-- coordinator reports.
CREATE TABLE delegations (
  address    BLOB PRIMARY KEY CHECK (length(address) IN (4, 16)),
  prefix_len INTEGER NOT NULL CHECK (prefix_len BETWEEN 0 AND length(address) * 8),
  last       BLOB NOT NULL CHECK (length(last) = length(address) AND last >= address),
  public_key BLOB NOT NULL REFERENCES peers ON UPDATE CASCADE ON DELETE CASCADE,
  reclaim    INTEGER NOT NULL DEFAULT 0 CHECK (reclaim IN (0, 1))
) STRICT, WITHOUT ROWID;

CREATE INDEX delegations_by_key ON delegations (public_key);
CREATE INDEX delegations_by_last ON delegations (last);

-- The CIDRs of the network, each keyed by its prefix. The parent of a CIDR is the smallest other
-- CIDR that holds it, and the CIDR of a peer that of its delegations. Every peer sees the peers of
-- an `infra` CIDR.
CREATE TABLE cidrs (
  address    BLOB NOT NULL CHECK (length(address) IN (4, 16)),  -- host bits zero
  prefix_len INTEGER NOT NULL CHECK (prefix_len BETWEEN 0 AND length(address) * 8),
  name       TEXT NOT NULL UNIQUE,
  infra      INTEGER NOT NULL DEFAULT 0 CHECK (infra IN (0, 1)),
  PRIMARY KEY (address, prefix_len)
) STRICT, WITHOUT ROWID;

CREATE TABLE pin_kinds (
  kind INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
) STRICT;

INSERT INTO pin_kinds VALUES (1, 'delegation');

-- Prefixes pinned to a public key: the delegation that each peer claims, aligned prefixes of
-- which a lone address is a /32 or /128. `claimed` tells whether the last announcement accepted
-- from the peer claims the prefix, so the prefixes of a key that are claimed are its claimed
-- delegation. Each pin holds the last address of its prefix, so that pins that overlap are found
-- by comparing addresses of the same length.
CREATE TABLE prefix_pins (
  address    BLOB NOT NULL CHECK (length(address) IN (4, 16)),  -- host bits zero
  prefix_len INTEGER NOT NULL CHECK (prefix_len BETWEEN 0 AND length(address) * 8),
  last       BLOB NOT NULL CHECK (length(last) = length(address) AND last >= address),
  public_key BLOB NOT NULL CHECK (length(public_key) = 32)
             REFERENCES peers ON DELETE RESTRICT,
  kind       INTEGER NOT NULL REFERENCES pin_kinds,
  claimed    INTEGER NOT NULL CHECK (claimed IN (0, 1)),
  PRIMARY KEY (address, prefix_len)
) STRICT, WITHOUT ROWID;

CREATE INDEX prefix_pins_by_key ON prefix_pins (public_key);
CREATE INDEX prefix_pins_by_last ON prefix_pins (last);

CREATE TABLE endpoint_kinds (
  kind INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
) STRICT;

INSERT INTO endpoint_kinds VALUES (0, 'endpoint'), (1, 'candidate'), (2, 'announced');

-- The endpoints of the peers: the endpoint and the candidates that the node records of a peer
-- apart from its announcements, as a client records what the coordinator reports, and the
-- coordinator what a peer that has never announced sets in plain HTTP, and the announced
-- endpoints, those that the last announcement accepted from a peer states, in the order of their
-- positions, the preferred first. Each is either an IP address or a domain name, with its own
-- port. They follow their peer when its key changes, and go with it when it is deleted.
CREATE TABLE endpoints (
  public_key BLOB NOT NULL CHECK (length(public_key) = 32)
             REFERENCES peers ON UPDATE CASCADE ON DELETE CASCADE,
  kind       INTEGER NOT NULL REFERENCES endpoint_kinds,
  position   INTEGER NOT NULL CHECK (position >= 0),
  address    BLOB CHECK (length(address) IN (4, 16)),
  domain     TEXT,
  port       INTEGER NOT NULL CHECK (port BETWEEN 0 AND 65535),
  CHECK ((address IS NULL) <> (domain IS NULL)),
  PRIMARY KEY (public_key, kind, position)
) STRICT, WITHOUT ROWID;

-- Each peer has at most one endpoint recorded apart from its announcements, besides its
-- candidates.
CREATE UNIQUE INDEX one_endpoint_per_key ON endpoints (public_key) WHERE kind = 0;

-- The last announcement accepted from each peer, as the node decoded it once it had checked its
-- signature, if it has one: its timestamp, whether it was signed, and the statements that the node
-- understands. Its claims are the pins: the claimed name is the name of the peer, and the claimed
-- delegation the claimed prefixes of `prefix_pins`. The primary IP and the nameserver are here;
-- the allowed IPs and the endpoints are in the table that follows and in `endpoints`. The signed
-- bytes aren't kept here.
CREATE TABLE announcements (
  public_key BLOB PRIMARY KEY CHECK (length(public_key) = 32)
             REFERENCES peers ON DELETE RESTRICT,
  timestamp  INTEGER NOT NULL CHECK (timestamp >= 0),
  signed     INTEGER NOT NULL CHECK (signed IN (0, 1)),
  primary_ip BLOB CHECK (length(primary_ip) IN (4, 16)),
  -- The nameserver that the peer offers for the names under its own, if any: its address, port
  -- and zone, all three or none.
  nameserver_address BLOB CHECK (length(nameserver_address) IN (4, 16)),
  nameserver_port    INTEGER CHECK (nameserver_port BETWEEN 1 AND 65535),
  nameserver_zone    TEXT,
  CHECK ((nameserver_address IS NULL) = (nameserver_port IS NULL)
     AND (nameserver_address IS NULL) = (nameserver_zone IS NULL))
) STRICT, WITHOUT ROWID;

-- The allowed IPs that the announcements state, as stated, before they are shrunk to the claimed
-- delegation, which go with their announcement when it is replaced.
CREATE TABLE announced_allowed_ips (
  public_key BLOB NOT NULL REFERENCES announcements ON DELETE CASCADE,
  address    BLOB NOT NULL CHECK (length(address) IN (4, 16)),  -- host bits zero
  prefix_len INTEGER NOT NULL CHECK (prefix_len BETWEEN 0 AND length(address) * 8),
  PRIMARY KEY (public_key, address, prefix_len)
) STRICT, WITHOUT ROWID;
