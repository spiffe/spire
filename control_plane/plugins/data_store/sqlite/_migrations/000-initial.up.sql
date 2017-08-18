CREATE TABLE federated_bundles (
  id          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  spiffe_id   VARCHAR(1024) NOT NULL,

  bundle      BLOB NOT NULL,
  ttl         INT  NOT NULL,

  created_at  TIMESTAMP NOT NULL,
  updated_at  TIMESTAMP NOT NULL,
  deleted_at  TIMESTAMP,

  CHECK(ttl>=0)
);

CREATE UNIQUE INDEX idx_federated_bundles_spiffe_id
  ON federated_bundles(spiffe_id)
  WHERE deleted_at IS NULL;

CREATE TABLE attested_node_entries (
  id            INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  spiffe_id     VARCHAR(1024) NOT NULL,

  data_type     TEXT      NOT NULL,
  serial_number TEXT      NOT NULL,
  expires_at    TIMESTAMP NOT NULL,

  created_at    TIMESTAMP NOT NULL,
  updated_at    TIMESTAMP NOT NULL,
  deleted_at    TIMESTAMP
);

CREATE UNIQUE INDEX idx_attested_node_entries_spiffe_id
  ON attested_node_entries(spiffe_id)
  WHERE deleted_at IS NULL;

CREATE TABLE node_resolver_map_entries (
  id             INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  spiffe_id      VARCHAR(1024) NOT NULL,

  type  TEXT NOT NULL,
  value TEXT NOT NULL,

  created_at     TIMESTAMP NOT NULL,
  updated_at     TIMESTAMP NOT NULL,
  deleted_at     TIMESTAMP
);

CREATE TABLE registered_entries (
  registered_entry_id   TEXT NOT NULL PRIMARY KEY,
  spiffe_id VARCHAR(1024) NOT NULL,
  parent_id VARCHAR(1024) NOT NULL,
  ttl       INT           NOT NULL
);

CREATE TABLE selectors (
  registered_entry_id   TEXT NOT NULL,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  PRIMARY KEY (registered_entry_id, type, value),
  FOREIGN KEY(registered_entry_id) REFERENCES registered_entries(registered_entry_id)
);

CREATE UNIQUE INDEX idx_node_resolver_map_entries_type_value
  ON node_resolver_map_entries(spiffe_id,type,value)
  WHERE deleted_at IS NULL;

CREATE INDEX idx_selectors_registered_entry_id ON selectors(registered_entry_id);
