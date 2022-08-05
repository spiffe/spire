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
		19: `
			PRAGMA foreign_keys=OFF;
			BEGIN TRANSACTION;
			CREATE TABLE IF NOT EXISTS "federated_registration_entries" ("bundle_id" integer,"registered_entry_id" integer, PRIMARY KEY ("bundle_id","registered_entry_id"));
			CREATE TABLE IF NOT EXISTS "bundles" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"data" blob );
			INSERT INTO bundles VALUES(1,'2022-08-05 15:36:32.8495472-03:00','2022-08-05 15:36:32.8858305-03:00','spiffe://example.org',X'0a147370696666653a2f2f6578616d706c652e6f726712d3030ad003308201cc30820153a00302010202090093380e1447d2f9ae300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138303531333139333334375a170d3233303531323139333334375a301e310b3009060355040613025553310f300d060355040a0c065350494646453076301006072a8648ce3d020106052b81040022036200045a307e9d2192c48622ce76fce31bb95860d98fcd272fb5b5737cdfe3c5a1cb499aed8ee60812b37d092b80382e2388f467ed3fb431ffafc82d3ad2cbac8a6e330587a1ee2f6d5045b5ed6f8fa5ede96784f255f0702bcbb3f99c9af3ea54af63a35d305b301d0603551d0e0416041487a5f357a2f035acc0f864c454e76ed3ba39c8e8300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630190603551d1104123010860e7370696666653a2f2f6c6f63616c300a06082a8648ce3d0403040367003064023013831ed77a8c0bd8ba164c74876eb2d3d41921bb91a80f69b8b83d01e780032a39b41cd197560bd0a344a74d9529260902305d789bea8c9f705b9e4e1a3d494300c50fb91678407aa0c9703db23fe61118ddacc98b5e88d2e375252613496192a9671a85010a5b3059301306072a8648ce3d020106082a8648ce3d03010703420004fb6842436c6dd21135a3b74965cf7ea977d44cd664b59dc4fa688f667754d9a56222d7335c2f95d7c22ff478744b123cf2cde64ba52812f1a50b05e473f40b8112204f6b6f4e6d4370526f74504f6c6634727867617033393434666d4a636670425018b0e9ba9706');
			CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"data_type" varchar(255),"serial_number" varchar(255),"expires_at" datetime,"new_serial_number" varchar(255),"new_expires_at" datetime,"can_reattest" bool );
			CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"type" varchar(255),"value" varchar(255) );
			CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255),"spiffe_id" varchar(255),"parent_id" varchar(255),"ttl" integer,"admin" bool,"downstream" bool,"expiry" bigint,"revision_number" bigint,"store_svid" bool,"hint" varchar(255),"x509_svid_ttl" integer,"jwt_svid_ttl" integer );
			CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"token" varchar(255),"expiry" bigint );
			CREATE TABLE IF NOT EXISTS "selectors" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"type" varchar(255),"value" varchar(255) );
			CREATE TABLE IF NOT EXISTS "migrations" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"version" integer,"code_version" varchar(255) );
			INSERT INTO migrations VALUES(1,'2022-08-05 15:36:32.7835313-03:00','2022-08-05 15:36:32.7835313-03:00',19,'1.4.1-dev-unk');
			CREATE TABLE IF NOT EXISTS "dns_names" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"value" varchar(255) );
			CREATE TABLE IF NOT EXISTS "federated_trust_domains" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"bundle_endpoint_url" varchar(255),"bundle_endpoint_profile" varchar(255),"endpoint_spiffe_id" varchar(255),"implicit" bool );
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
			CREATE UNIQUE INDEX uix_registered_entries_entry_id ON "registered_entries"(entry_id) ;
			CREATE UNIQUE INDEX uix_join_tokens_token ON "join_tokens"("token") ;
			CREATE INDEX idx_selectors_type_value ON "selectors"("type", "value") ;
			CREATE UNIQUE INDEX idx_selector_entry ON "selectors"(registered_entry_id, "type", "value") ;
			CREATE UNIQUE INDEX idx_dns_entry ON "dns_names"(registered_entry_id, "value") ;
			CREATE UNIQUE INDEX uix_federated_trust_domains_trust_domain ON "federated_trust_domains"(trust_domain) ;
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
