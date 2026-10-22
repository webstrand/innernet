-- Version 1 of the schema of a node's database: what every node stores of the peers of its
-- network, whatever its role. A coordinator adds tables of its own, its annex, beside these, and
-- may use columns that other nodes leave at their defaults. Public keys are their 32 raw bytes,
-- and addresses their 4 (IPv4) or 16 (IPv6) bytes in network order.
--
-- The schema holds what keeps the database consistent: types, checks, keys and references. What
-- a node accepts and keeps, such as what stays pinned to a key, is decided by the node's code, so
-- that an operator who must repair a database can edit it with `sqlite3`, deleting the rows that
-- refer to a row before the row itself.

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
  tls                           INTEGER NOT NULL DEFAULT 0 CHECK (tls IN (0, 1))
) STRICT, WITHOUT ROWID;

-- No name belongs to two peers.
CREATE UNIQUE INDEX names_once ON peers (name);

-- The delegations of the peers: the aligned prefixes that the coordinator assigns each peer,
-- whose addresses are routed to the peer and accepted from it. A lone address is a /32 or /128.
-- `address` is the first address of the prefix, whose host bits are zero, and `last` its last
-- address, so that the delegation of an address, and delegations that overlap, are found by
-- comparing addresses of the same length. A client records the delegations that the coordinator
-- reports. They follow their peer when its key changes, and go with it when it is deleted.
CREATE TABLE delegations (
  address    BLOB PRIMARY KEY CHECK (length(address) IN (4, 16)),
  prefix_len INTEGER NOT NULL CHECK (prefix_len BETWEEN 0 AND length(address) * 8),
  last       BLOB NOT NULL CHECK (length(last) = length(address) AND last >= address),
  public_key BLOB NOT NULL REFERENCES peers ON UPDATE CASCADE ON DELETE CASCADE
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

-- Prefixes pinned to a public key: every delegation that the node has accepted for a peer, aligned
-- prefixes of which a lone address is a /32 or /128. The pins of a key accumulate and may nest, so
-- that a delegation that the coordinator withdraws stays pinned. Each pin holds the last address of
-- its prefix, so that pins that overlap are found by comparing addresses of the same length.
CREATE TABLE prefix_pins (
  address    BLOB NOT NULL CHECK (length(address) IN (4, 16)),  -- host bits zero
  prefix_len INTEGER NOT NULL CHECK (prefix_len BETWEEN 0 AND length(address) * 8),
  last       BLOB NOT NULL CHECK (length(last) = length(address) AND last >= address),
  public_key BLOB NOT NULL CHECK (length(public_key) = 32)
             REFERENCES peers ON DELETE RESTRICT,
  kind       INTEGER NOT NULL REFERENCES pin_kinds,
  PRIMARY KEY (address, prefix_len)
) STRICT, WITHOUT ROWID;

CREATE INDEX prefix_pins_by_key ON prefix_pins (public_key);
CREATE INDEX prefix_pins_by_last ON prefix_pins (last);

CREATE TABLE endpoint_kinds (
  kind INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
) STRICT;

INSERT INTO endpoint_kinds VALUES (0, 'endpoint'), (1, 'candidate');

-- The endpoints of the peers: the endpoint of each and its candidates, in the order of their
-- positions. Each is either an IP address or a domain name, with its own port. They follow their
-- peer when its key changes, and go with it when it is deleted.
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

-- Each peer has at most one endpoint, besides its candidates.
CREATE UNIQUE INDEX one_endpoint_per_key ON endpoints (public_key) WHERE kind = 0;
