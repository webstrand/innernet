-- The coordinator's annex: what only the coordinator keeps, beside the tables of every node.

-- Which CIDRs see each other's peers, besides their own and those of the infra CIDRs, each pair
-- once, in either order. A CIDR is deleted only once no association names it.
CREATE TABLE associations (
  address_1    BLOB NOT NULL,
  prefix_len_1 INTEGER NOT NULL,
  address_2    BLOB NOT NULL,
  prefix_len_2 INTEGER NOT NULL,
  PRIMARY KEY (address_1, prefix_len_1, address_2, prefix_len_2),
  FOREIGN KEY (address_1, prefix_len_1) REFERENCES cidrs ON DELETE RESTRICT,
  FOREIGN KEY (address_2, prefix_len_2) REFERENCES cidrs ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;
