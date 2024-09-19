package sqlstore

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/blang/semver/v4"
)

var (
	// migrationDumps is the state of the database at the indicated schema
	// version that the database is initialized to when doing migration tests.
	// It can be obtained by running `sqlite3 datastore.sqlite3 .dump` on a
	// pristine database created by a SPIRE release that runs that schema
	// version.
	migrationDumps = map[int]string{
		23: `
			PRAGMA foreign_keys=OFF;
			BEGIN TRANSACTION;
			CREATE TABLE IF NOT EXISTS "federated_registration_entries" ("bundle_id" integer,"registered_entry_id" integer, PRIMARY KEY ("bundle_id","registered_entry_id"));
			CREATE TABLE IF NOT EXISTS "bundles" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"data" blob );
			INSERT INTO bundles VALUES(1,'2023-08-29 13:15:25.103258-03:00','2023-08-29 13:15:25.201436-03:00','spiffe://example.org',X'0a147370696666653a2f2f6578616d706c652e6f726712df030adc03308201d83082015ea0030201020214449db4c88cda977653f4d5e4770aec9b4b1e970c300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3233303531353032303530365a170d3238303531333032303530365a301e310b3009060355040613025553310f300d060355040a0c065350494646453076301006072a8648ce3d020106052b8104002203620004f57073b72f16fdec785ebd117735018227bfa2475a51385e485d0f42f540693b1768fd49ef2bf40e195ac38e48ec2bfd1cfdb51ce98cc48959d177aab0e97db0ce47e7b1c1416bb46c83577f0e2375e1dd079be4d57c8dc81410c5e5294b1867a35d305b301d0603551d0e04160414928ae360c6aaa7cf6aff8d1716b0046aa61c10ff300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630190603551d1104123010860e7370696666653a2f2f6c6f63616c300a06082a8648ce3d0403040368003065023100e7843c85f844778a95c9cc1b2cdcce9bf1d0ae9d67d7e6b6c5cf3c894d37e8530f6a7711d4f2ea82c3833df5b2b6d75102300a2287548b879888c6bdf88dab55b8fc80ec490059f484b2c4177403997b463e9011b3da82f8a6e29254eee45a6293641a85010a5b3059301306072a8648ce3d020106082a8648ce3d030107034200045cdd2166a5ae9e1c95695558c35dabc43c44c196abbd364aff4ffaac924811d7ab4601485f61efd5422ffe67b46f9d7c0b3963f90a41183d410bd3520c7434e5122054314a6772794c4746774f516c354e6b44386e4f7051695a43436430626b7a49189dd6bda7062801');
			CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"data_type" varchar(255),"serial_number" varchar(255),"expires_at" datetime,"new_serial_number" varchar(255),"new_expires_at" datetime,"can_reattest" bool );
			CREATE TABLE IF NOT EXISTS "attested_node_entries_events" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255) );
			CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"type" varchar(255),"value" varchar(255) );
			CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255),"spiffe_id" varchar(255),"parent_id" varchar(255),"ttl" integer,"admin" bool,"downstream" bool,"expiry" bigint,"revision_number" bigint,"store_svid" bool,"hint" varchar(255),"jwt_svid_ttl" integer );
			CREATE TABLE IF NOT EXISTS "registered_entries_events" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255) );
			CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"token" varchar(255),"expiry" bigint );
			CREATE TABLE IF NOT EXISTS "selectors" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"type" varchar(255),"value" varchar(255) );
			CREATE TABLE IF NOT EXISTS "migrations" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"version" integer,"code_version" varchar(255) );
			INSERT INTO migrations VALUES(1,'2023-08-29 13:15:25.080937-03:00','2023-08-29 13:15:25.080937-03:00',23,'1.8.0-dev-unk');
			CREATE TABLE IF NOT EXISTS "dns_names" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"value" varchar(255) );
			CREATE TABLE IF NOT EXISTS "federated_trust_domains" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"bundle_endpoint_url" varchar(255),"bundle_endpoint_profile" varchar(255),"endpoint_spiffe_id" varchar(255),"implicit" bool );
			CREATE TABLE IF NOT EXISTS "ca_journals" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"data" blob,"active_x509_authority_id" varchar(255),"active_jwt_authority_id" varchar(255) );
			DELETE FROM sqlite_sequence;
			INSERT INTO sqlite_sequence VALUES('migrations',1);
			INSERT INTO sqlite_sequence VALUES('bundles',1);
			CREATE UNIQUE INDEX uix_bundles_trust_domain ON "bundles"(trust_domain) ;
			CREATE INDEX idx_attested_node_entries_expires_at ON "attested_node_entries"(expires_at) ;
			CREATE UNIQUE INDEX uix_attested_node_entries_spiffe_id ON "attested_node_entries"(spiffe_id) ;
			CREATE UNIQUE INDEX idx_node_resolver_map ON "node_resolver_map_entries"(spiffe_id, "type", "value") ;
			CREATE INDEX idx_registered_entries_spiffe_id ON "registered_entries"(spiffe_id) ;
			CREATE INDEX idx_registered_entries_parent_id ON "registered_entries"(parent_id) ;
			CREATE INDEX idx_registered_entries_expiry ON "registered_entries"("expiry") ;
			CREATE INDEX idx_registered_entries_hint ON "registered_entries"("hint") ;
			CREATE UNIQUE INDEX uix_registered_entries_entry_id ON "registered_entries"(entry_id) ;
			CREATE UNIQUE INDEX uix_join_tokens_token ON "join_tokens"("token") ;
			CREATE INDEX idx_selectors_type_value ON "selectors"("type", "value") ;
			CREATE UNIQUE INDEX idx_selector_entry ON "selectors"(registered_entry_id, "type", "value") ;
			CREATE UNIQUE INDEX idx_dns_entry ON "dns_names"(registered_entry_id, "value") ;
			CREATE UNIQUE INDEX uix_federated_trust_domains_trust_domain ON "federated_trust_domains"(trust_domain) ;
			CREATE INDEX idx_ca_journals_active_x509_authority_id ON "ca_journals"(active_x509_authority_id) ;
			CREATE INDEX idx_ca_journals_active_jwt_authority_id ON "ca_journals"(active_jwt_authority_id) ;
			CREATE INDEX idx_federated_registration_entries_registered_entry_id ON "federated_registration_entries"(registered_entry_id) ;
			COMMIT;
			`,
	}
)

func dumpDB(t *testing.T, path string, statements string) {
	db, err := sql.Open("sqlite3", path)
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, db.Close())
	}()
	_, err = db.Exec(statements)
	require.NoError(t, err)
}

func TestGetDBCodeVersion(t *testing.T) {
	tests := []struct {
		desc            string
		storedMigration Migration
		expectVersion   semver.Version
		expectErr       string
	}{
		{
			desc:            "no code version",
			storedMigration: Migration{},
			expectVersion:   semver.Version{},
		},
		{
			desc:            "code version, valid",
			storedMigration: Migration{CodeVersion: "1.2.3"},
			expectVersion:   semver.Version{Major: 1, Minor: 2, Patch: 3, Pre: nil, Build: nil},
		},
		{
			desc:            "code version, invalid",
			storedMigration: Migration{CodeVersion: "a.2*.3"},
			expectErr:       "unable to parse code version from DB: Invalid character(s) found in major number \"a\"",
		},
	}

	for _, tt := range tests {
		tt := tt // alias loop variable as it is used in the closure
		t.Run(tt.desc, func(t *testing.T) {
			retVersion, err := getDBCodeVersion(tt.storedMigration)

			if tt.expectErr != "" {
				assert.Equal(t, semver.Version{}, retVersion)
				assert.Equal(t, tt.expectErr, err.Error())
				return
			}

			assert.Equal(t, tt.expectVersion, retVersion)
			assert.NoError(t, err)
		})
	}
}

func TestIsCompatibleCodeVersion(t *testing.T) {
	tests := []struct {
		desc             string
		thisCodeVersion  semver.Version
		dbCodeVersion    semver.Version
		expectCompatible bool
	}{
		{
			desc:             "backwards compatible 1 minor version",
			thisCodeVersion:  codeVersion,
			dbCodeVersion:    semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor - 1)},
			expectCompatible: true,
		},
		{
			desc:             "forwards compatible 1 minor version",
			thisCodeVersion:  codeVersion,
			dbCodeVersion:    semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor + 1)},
			expectCompatible: true,
		},
		{
			desc:             "compatible with self",
			thisCodeVersion:  codeVersion,
			dbCodeVersion:    codeVersion,
			expectCompatible: true,
		},
		{
			desc:             "not backwards compatible 2 minor versions",
			thisCodeVersion:  codeVersion,
			dbCodeVersion:    semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor - 2)},
			expectCompatible: false,
		},
		{
			desc:             "not forwards compatible 2 minor versions",
			thisCodeVersion:  codeVersion,
			dbCodeVersion:    semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor + 2)},
			expectCompatible: false,
		},
		{
			desc:             "not compatible with different major version but same minor",
			thisCodeVersion:  codeVersion,
			dbCodeVersion:    semver.Version{Major: (codeVersion.Major + 1), Minor: codeVersion.Minor},
			expectCompatible: false,
		},
	}

	for _, tt := range tests {
		tt := tt // alias loop variable as it is used in the closure
		t.Run(tt.desc, func(t *testing.T) {
			compatible := isCompatibleCodeVersion(tt.thisCodeVersion, tt.dbCodeVersion)

			assert.Equal(t, tt.expectCompatible, compatible)
		})
	}
}

func TestIsDisabledMigrationAllowed(t *testing.T) {
	tests := []struct {
		desc          string
		dbCodeVersion semver.Version
		expectErr     string
	}{
		{
			desc:          "allowed",
			dbCodeVersion: semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor + 1)},
		},
		{
			desc:          "not allowed, versioning",
			dbCodeVersion: semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor + 2)},
			expectErr:     "auto-migration must be enabled for current DB",
		},
	}

	for _, tt := range tests {
		tt := tt // alias loop variable as it is used in the closure
		t.Run(tt.desc, func(t *testing.T) {
			err := isDisabledMigrationAllowed(codeVersion, tt.dbCodeVersion)

			if tt.expectErr != "" {
				require.Error(t, err)
				assert.Equal(t, tt.expectErr, err.Error())
				return
			}

			assert.NoError(t, err)
		})
	}
}
