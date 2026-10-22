-- The coordinator's annex: what only the coordinator keeps, beside the tables of every node.

-- The associations of CIDRs, whose peers see each other's: each names its two CIDRs by their
-- prefixes, the lower first, in the order of prefixes, so that a pair is held once. A CIDR is
-- deleted only once no association names it.
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
