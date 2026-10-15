-- Version 1 of the data store: the peers and CIDRs that the coordination server reported, and the
-- addresses pinned to the peers' public keys. Server IDs are not stored. Public keys are their 32
-- raw bytes, and addresses their 4 (IPv4) or 16 (IPv6) bytes in network order.

PRAGMA application_id = 1768844914; -- "innr"

CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value ANY
) STRICT, WITHOUT ROWID;

-- The lowest version of the schema that a binary must know to open the data store. A migration
-- raises it only if a binary that doesn't know the migration would break an invariant it adds.
INSERT INTO meta VALUES ('min_reader_version', 1);

-- The peers, as the coordination server last reported them.
CREATE TABLE peers (
  public_key                    BLOB PRIMARY KEY CHECK (length(public_key) = 32),
  name                          TEXT NOT NULL,
  is_admin                      INTEGER NOT NULL CHECK (is_admin IN (0, 1)),
  is_disabled                   INTEGER NOT NULL CHECK (is_disabled IN (0, 1)),
  is_redeemed                   INTEGER NOT NULL CHECK (is_redeemed IN (0, 1)),
  persistent_keepalive_interval INTEGER CHECK (persistent_keepalive_interval BETWEEN 0 AND 65535),
  invite_expires                INTEGER  -- UNIX time in seconds
) STRICT, WITHOUT ROWID;

CREATE TABLE pin_kinds (
  kind INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
) STRICT;

INSERT INTO pin_kinds VALUES (0, 'address');

-- Prefixes pinned to a public key. A pin never moves to another key, nor changes, and is never
-- deleted: the triggers below refuse it, and with recursive_triggers on they also refuse the
-- deletion that REPLACE would make to resolve a conflict.
CREATE TABLE prefix_pins (
  address    BLOB NOT NULL CHECK (length(address) IN (4, 16)),  -- host bits zero
  prefix_len INTEGER NOT NULL CHECK (prefix_len BETWEEN 0 AND length(address) * 8),
  public_key BLOB NOT NULL CHECK (length(public_key) = 32)
             REFERENCES peers ON DELETE RESTRICT,
  kind       INTEGER NOT NULL REFERENCES pin_kinds,
  PRIMARY KEY (address, prefix_len),
  -- A peer's address is a single address.
  CHECK (kind <> 0 OR prefix_len = length(address) * 8)
) STRICT, WITHOUT ROWID;

-- Each peer has one address.
CREATE UNIQUE INDEX one_address_per_key ON prefix_pins (public_key) WHERE kind = 0;

CREATE TRIGGER pins_never_change BEFORE UPDATE ON prefix_pins
BEGIN
  SELECT RAISE(ABORT, 'pins never change');
END;

CREATE TRIGGER pins_never_deleted BEFORE DELETE ON prefix_pins
BEGIN
  SELECT RAISE(ABORT, 'pins are never deleted');
END;

-- A peer is never deleted either, since its pins refer to it.
CREATE TRIGGER peers_never_deleted BEFORE DELETE ON peers
BEGIN
  SELECT RAISE(ABORT, 'peers are never deleted');
END;

CREATE TABLE endpoint_kinds (
  kind INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
) STRICT;

INSERT INTO endpoint_kinds VALUES (0, 'endpoint'), (1, 'candidate');

-- The endpoints of the peers, as the coordination server last reported them. Each is either an
-- IP address or a domain name, with its own port.
CREATE TABLE endpoints (
  public_key BLOB NOT NULL CHECK (length(public_key) = 32)
             REFERENCES peers ON DELETE CASCADE,
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

-- The CIDRs, as the coordination server last reported them. Their parents and the CIDRs of the
-- peers follow from containment.
CREATE TABLE cidrs (
  address    BLOB NOT NULL CHECK (length(address) IN (4, 16)),  -- host bits zero
  prefix_len INTEGER NOT NULL CHECK (prefix_len BETWEEN 0 AND length(address) * 8),
  name       TEXT NOT NULL,
  PRIMARY KEY (address, prefix_len)
) STRICT, WITHOUT ROWID;
