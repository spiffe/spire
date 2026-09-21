CREATE TABLE IF NOT EXISTS registered_entries (
    created_at timestamp STATIC,
    updated_at timestamp, --- not static for exotic cassandra big-brain reasons
    entry_id text,
    spiffe_id text STATIC,
    parent_id text STATIC,
    ttl int STATIC,
    admin boolean STATIC,
    downstream boolean STATIC,
    expiry bigint STATIC,
    revision_number bigint STATIC,
    store_svid boolean STATIC,
    hint text STATIC,
    jwt_svid_ttl int STATIC,
    selector_types frozen<list<text>> STATIC,
    selector_values frozen<list<text>> STATIC,
    unrolled_selector_type_val text,
    unrolled_ftd text,
    dns_names set<text> STATIC,
    federated_trust_domains set<text> STATIC,
    index_terms set<text> STATIC,
    selector_type_value_full frozen<list<text>> STATIC,
    federated_trust_domains_full frozen<list<text>> STATIC,
    PRIMARY KEY (entry_id, unrolled_selector_type_val, unrolled_ftd)
);

CREATE INDEX IF NOT EXISTS parent_id_idx ON registered_entries (parent_id) USING 'sai';
CREATE INDEX IF NOT EXISTS spiffe_id_idx ON registered_entries (spiffe_id) USING 'sai';
CREATE INDEX IF NOT EXISTS hint_idx ON registered_entries (hint) USING 'sai';
CREATE INDEX IF NOT EXISTS federated_trust_domain_idx ON registered_entries (federated_trust_domains) USING 'sai';
CREATE INDEX IF NOT EXISTS downstream_idx ON registered_entries (downstream) USING 'sai';
CREATE INDEX IF NOT EXISTS expiry_idx ON registered_entries (expiry) USING 'sai';
CREATE INDEX IF NOT EXISTS indices_idx ON registered_entries (index_terms) USING 'sai';
CREATE INDEX IF NOT EXISTS unrolled_ftd_idx ON registered_entries (unrolled_ftd) USING 'sai';
CREATE INDEX IF NOT EXISTS unrolled_selector_type_val_idx ON registered_entries (unrolled_selector_type_val) USING 'sai';
CREATE INDEX IF NOT EXISTS selector_type_value_full_idx ON registered_entries (FULL(selector_type_value_full)) USING 'sai';
CREATE INDEX IF NOT EXISTS federated_trust_domains_full_idx ON registered_entries (FULL(federated_trust_domains_full)) USING 'sai';

CREATE TABLE IF NOT EXISTS registration_entry_events (
    id int,
    created_at timestamp,
    updated_at timestamp,
    entry_id varchar,
    PRIMARY KEY(entry_id, id)
);  
CREATE INDEX IF NOT EXISTS registration_entry_events_entry_id_idx ON registration_entry_events (id) USING 'sai';

CREATE TABLE IF NOT EXISTS attested_node_entries (
    created_at timestamp STATIC,
    updated_at timestamp,
    spiffe_id varchar,
    attestation_data_type varchar STATIC,
    serial_number varchar STATIC,
    banned boolean STATIC,
    cert_not_after bigint STATIC,
    new_serial_number varchar STATIC,
    new_cert_not_after bigint STATIC,
    can_reattest boolean STATIC,
    agent_version varchar STATIC,
    selector_type_value varchar,
    selector_type_value_full frozen<list<text>> STATIC,
    index_terms set<text> STATIC,
    PRIMARY KEY (spiffe_id, selector_type_value)
);

CREATE INDEX IF NOT EXISTS cert_not_after_idx ON attested_node_entries (cert_not_after) USING 'sai';
CREATE INDEX IF NOT EXISTS selector_type_value_idx ON attested_node_entries (selector_type_value) USING 'sai';
CREATE INDEX IF NOT EXISTS selector_type_value_full_idx ON attested_node_entries (FULL(selector_type_value_full)) USING 'sai';
CREATE INDEX IF NOT EXISTS serial_number_idx ON attested_node_entries (serial_number) USING 'sai';
CREATE INDEX IF NOT EXISTS banned_idx ON attested_node_entries (banned) USING 'sai';
CREATE INDEX IF NOT EXISTS index_terms_idx ON attested_node_entries (index_terms) USING 'sai';

CREATE TABLE IF NOT EXISTS attested_node_entries_events (
    event_id int,
    created_at timestamp,
    updated_at timestamp,
    spiffe_id varchar,
    PRIMARY KEY (spiffe_id, event_id)
);
CREATE INDEX IF NOT EXISTS attested_node_entries_events_event_id_idx ON attested_node_entries_events (event_id) USING 'sai';
CREATE INDEX IF NOT EXISTS attested_node_entries_events_created_at_idx ON attested_node_entries_events (created_at) USING 'sai';

CREATE TABLE IF NOT EXISTS bundles (
    created_at timestamp STATIC,
    updated_at timestamp STATIC,
    trust_domain varchar,
    data blob STATIC, --- this is static because the bundle data is the same across all rows
    federated_entry_id varchar,
    PRIMARY KEY (trust_domain, federated_entry_id),
);
CREATE INDEX IF NOT EXISTS federated_entry_id_idx ON bundles (federated_entry_id) USING 'sai';

CREATE TABLE IF NOT EXISTS ca_journals (
    id int,
    created_at timestamp,
    updated_at timestamp,
    data blob,
    active_x509_authority_id varchar,
    PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ca_journals_active_idx ON ca_journals (active_x509_authority_id) USING 'sai';

CREATE TABLE IF NOT EXISTS federated_trust_domains (
    created_at timestamp,
    updated_at timestamp,
    trust_domain varchar,
    bundle_endpoint_url varchar,
    bundle_endpoint_profile varchar,
    endpoint_spiffe_id varchar,
    -- implicit boolean, --- pretty sure this can be dropped in upstream sqlstore
    PRIMARY KEY (trust_domain)
);

CREATE TABLE IF NOT EXISTS join_tokens (
    join_token varchar,
    expiry bigint,
    PRIMARY KEY (join_token)
);
CREATE INDEX IF NOT EXISTS expiry_idx ON join_tokens (expiry) USING 'sai';