-- The coordinator's annex to the node's schema: what only the coordinator holds.

-- The name that the coordinator offers each peer, in canonical hostname(7) format, of which the
-- peer claims its name in its announcements, and which names a peer that has never announced. No
-- name is offered to two peers.
CREATE TABLE offered_names (
  public_key BLOB PRIMARY KEY REFERENCES peers ON UPDATE CASCADE ON DELETE CASCADE,
  name       TEXT NOT NULL UNIQUE
) STRICT, WITHOUT ROWID;

-- The associations of CIDRs, whose peers see each other's: each names its two CIDRs by their
-- prefixes, the lower first, in the order of prefixes, so that a pair is held once.
CREATE TABLE associations (
  address_1    BLOB NOT NULL,
  prefix_len_1 INTEGER NOT NULL,
  address_2    BLOB NOT NULL,
  prefix_len_2 INTEGER NOT NULL,
  PRIMARY KEY (address_1, prefix_len_1, address_2, prefix_len_2),
  FOREIGN KEY (address_1, prefix_len_1) REFERENCES cidrs (address, prefix_len)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  FOREIGN KEY (address_2, prefix_len_2) REFERENCES cidrs (address, prefix_len)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  -- IPv4 before IPv6, then by address, then by length, as prefixes are ordered.
  CHECK ((length(address_1), address_1, prefix_len_1) < (length(address_2), address_2, prefix_len_2))
) STRICT, WITHOUT ROWID;
