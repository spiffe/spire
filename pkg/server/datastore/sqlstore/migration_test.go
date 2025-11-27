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
		24: `
		    PRAGMA foreign_keys=OFF;
            BEGIN TRANSACTION;
            CREATE TABLE IF NOT EXISTS "federated_registration_entries" ("bundle_id" integer,"registered_entry_id" integer, PRIMARY KEY ("bundle_id","registered_entry_id"));
            CREATE TABLE IF NOT EXISTS "bundles" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"data" blob );
            INSERT INTO bundles VALUES(1,'2025-11-27 22:38:52.925885+00:00','2025-11-27 22:39:08.716042+00:00','spiffe://example.org',X'0a147370696666653a2f2f6578616d706c652e6f726712df030adc03308201d83082015ea0030201020214449db4c88cda977653f4d5e4770aec9b4b1e970c300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3233303531353032303530365a170d3238303531333032303530365a301e310b3009060355040613025553310f300d060355040a0c065350494646453076301006072a8648ce3d020106052b8104002203620004f57073b72f16fdec785ebd117735018227bfa2475a51385e485d0f42f540693b1768fd49ef2bf40e195ac38e48ec2bfd1cfdb51ce98cc48959d177aab0e97db0ce47e7b1c1416bb46c83577f0e2375e1dd079be4d57c8dc81410c5e5294b1867a35d305b301d0603551d0e04160414928ae360c6aaa7cf6aff8d1716b0046aa61c10ff300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630190603551d1104123010860e7370696666653a2f2f6c6f63616c300a06082a8648ce3d0403040368003065023100e7843c85f844778a95c9cc1b2cdcce9bf1d0ae9d67d7e6b6c5cf3c894d37e8530f6a7711d4f2ea82c3833df5b2b6d75102300a2287548b879888c6bdf88dab55b8fc80ec490059f484b2c4177403997b463e9011b3da82f8a6e29254eee45a6293641a85010a5b3059301306072a8648ce3d020106082a8648ce3d03010703420004df7861b02a59e0afd752c0bfad8a11a6f0210289dccb1b58fcc85a92b1e3475b891f65d06df61feb1581452f1f7205d9cd2e30439c97dc0a7023d9caf8a63db812205a5577616d4764333178446e79614459704c70536e3449564b454b346a33545518fcc8a8c9061a85010a5b3059301306072a8648ce3d020106082a8648ce3d03010703420004755093caa518ea29a86ce57ba78addcecbe041770b63690d16b67c92f4726f4790948ba153e23b563e8fcc4463bce2ae46e73d71bfb05d5e2583d00b5e947a2512205a6a67344b4873736144585950376233445a446b5341744f627a456b476c7a6c188cc9a8c9062802');
            CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"data_type" varchar(255),"serial_number" varchar(255),"expires_at" datetime,"new_serial_number" varchar(255),"new_expires_at" datetime,"can_reattest" bool );
            CREATE TABLE IF NOT EXISTS "attested_node_entries_events" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255) );
            CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"type" varchar(255),"value" varchar(255) );
            CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255),"spiffe_id" varchar(255),"parent_id" varchar(255),"ttl" integer,"admin" bool,"downstream" bool,"expiry" bigint,"revision_number" bigint,"store_svid" bool,"hint" varchar(255),"jwt_svid_ttl" integer,"cache_hint_flags" blob );
            CREATE TABLE IF NOT EXISTS "registered_entries_events" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255) );
            CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"token" varchar(255),"expiry" bigint );
            CREATE TABLE IF NOT EXISTS "selectors" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"type" varchar(255),"value" varchar(255) );
            CREATE TABLE IF NOT EXISTS "migrations" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"version" integer,"code_version" varchar(255) );
            INSERT INTO migrations VALUES(1,'2025-11-27 22:38:52.916517+00:00','2025-11-27 22:38:52.916517+00:00',24,'1.14.0-dev-unk');
            CREATE TABLE IF NOT EXISTS "dns_names" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"value" varchar(255) );
            CREATE TABLE IF NOT EXISTS "federated_trust_domains" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"bundle_endpoint_url" varchar(255),"bundle_endpoint_profile" varchar(255),"endpoint_spiffe_id" varchar(255),"implicit" bool );
            CREATE TABLE IF NOT EXISTS "ca_journals" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"data" blob,"active_x509_authority_id" varchar(255),"active_jwt_authority_id" varchar(255) );
            INSERT INTO ca_journals VALUES(1,'2025-11-27 22:38:52.926142+00:00','2025-11-27 22:38:52.927057+00:00',X'0a97090a014110fca5a3c9061a96043082021230820198a00302010202104b7c57cdd409f4e4beff2fd3841f0d49300a06082a8648ce3d040303301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3235313132373232333834325a170d3235313132383232333835325a3050310b3009060355040613025553310f300d060355040a13065350494646453130302e060355040513273236323533333634313632333534323032313737303238343631393534373635303838353432363059301306072a8648ce3d020106082a8648ce3d03010703420004a504f26372e87d4952379b970a41048c7ab40e378599a3da1cd54386c90ffd9e1bc583d9c1a2b0931f3bfb552bfb4c6d01a54cbed0bf5c218ee9a936ebfdf82ca38185308182300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e04160414c7119341a904cddfb8bbedd37c099f22aa40337b301f0603551d23041830168014928ae360c6aaa7cf6aff8d1716b0046aa61c10ff301f0603551d110418301686147370696666653a2f2f6578616d706c652e6f7267300a06082a8648ce3d0403030368003065023014490296e27bc6d879103906d5d01bbdb63cbc6263e7d583713cb9fa8dde7f0188f7cba8e29b2130f1d8d6d56c739beb023100dbefdaf5f8d78b34d63e97843316aca3d1996a372911c38d73ef2f19a9dc4f555d4427c49c089d17d677a9a2aac884742296043082021230820198a00302010202104b7c57cdd409f4e4beff2fd3841f0d49300a06082a8648ce3d040303301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3235313132373232333834325a170d3235313132383232333835325a3050310b3009060355040613025553310f300d060355040a13065350494646453130302e060355040513273236323533333634313632333534323032313737303238343631393534373635303838353432363059301306072a8648ce3d020106082a8648ce3d03010703420004a504f26372e87d4952379b970a41048c7ab40e378599a3da1cd54386c90ffd9e1bc583d9c1a2b0931f3bfb552bfb4c6d01a54cbed0bf5c218ee9a936ebfdf82ca38185308182300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e04160414c7119341a904cddfb8bbedd37c099f22aa40337b301f0603551d23041830168014928ae360c6aaa7cf6aff8d1716b0046aa61c10ff301f0603551d110418301686147370696666653a2f2f6578616d706c652e6f7267300a06082a8648ce3d0403030368003065023014490296e27bc6d879103906d5d01bbdb63cbc6263e7d583713cb9fa8dde7f0188f7cba8e29b2130f1d8d6d56c739beb023100dbefdaf5f8d78b34d63e97843316aca3d1996a372911c38d73ef2f19a9dc4f555d4427c49c089d17d677a9a2aac88474280332286337313139333431613930346364646662386262656464333763303939663232616134303333376238fcc8a8c90642283932386165333630633661616137636636616666386431373136623030343661613631633130666612b2010a014110fca5a3c90618fcc8a8c90622205a5577616d4764333178446e79614459704c70536e3449564b454b346a3354552a5b3059301306072a8648ce3d020106082a8648ce3d03010703420004df7861b02a59e0afd752c0bfad8a11a6f0210289dccb1b58fcc85a92b1e3475b891f65d06df61feb1581452f1f7205d9cd2e30439c97dc0a7023d9caf8a63db830033a205a5577616d4764333178446e79614459704c70536e3449564b454b346a335455','c7119341a904cddfb8bbedd37c099f22aa40337b','');
            INSERT INTO ca_journals VALUES(2,'2025-11-27 22:39:08.714878+00:00','2025-11-27 22:39:08.716313+00:00',X'0a97090a0141108ca6a3c9061a96043082021230820199a003020102021100eb4caf13fe59fe74ab456093810bb241300a06082a8648ce3d040303301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3235313132373232333835385a170d3235313132383232333930385a3050310b3009060355040613025553310f300d060355040a13065350494646453130302e060355040513273130313330343837333231343837323132343839353738393230303936333036303430373638363059301306072a8648ce3d020106082a8648ce3d0301070342000497a28fef0c85936ff3e2451c5341e1176ea41a5f8f2a412b3bd89dbf24b90600f6e6cdb8193363105f711e0f11d2a1ac563d89234500bf2fd5ddf1689707560aa38185308182300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e04160414d34d1428b3efa1383b80bcb2ae752f26eda6e8b9301f0603551d23041830168014928ae360c6aaa7cf6aff8d1716b0046aa61c10ff301f0603551d110418301686147370696666653a2f2f6578616d706c652e6f7267300a06082a8648ce3d04030303670030640230477b1b9dab150250286f216ccf018f92fc2cd8ffc560678e9392d2f0e3a44797e9b483f101b1b9d81251dc06aec1bc8602305c045d243451d6966673dfe67bf1c7089b62b1baf1625b8bcfc4de637d34e94edafcd5add0c72acb6032215b933ffb8e2296043082021230820199a003020102021100eb4caf13fe59fe74ab456093810bb241300a06082a8648ce3d040303301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3235313132373232333835385a170d3235313132383232333930385a3050310b3009060355040613025553310f300d060355040a13065350494646453130302e060355040513273130313330343837333231343837323132343839353738393230303936333036303430373638363059301306072a8648ce3d020106082a8648ce3d0301070342000497a28fef0c85936ff3e2451c5341e1176ea41a5f8f2a412b3bd89dbf24b90600f6e6cdb8193363105f711e0f11d2a1ac563d89234500bf2fd5ddf1689707560aa38185308182300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e04160414d34d1428b3efa1383b80bcb2ae752f26eda6e8b9301f0603551d23041830168014928ae360c6aaa7cf6aff8d1716b0046aa61c10ff301f0603551d110418301686147370696666653a2f2f6578616d706c652e6f7267300a06082a8648ce3d04030303670030640230477b1b9dab150250286f216ccf018f92fc2cd8ffc560678e9392d2f0e3a44797e9b483f101b1b9d81251dc06aec1bc8602305c045d243451d6966673dfe67bf1c7089b62b1baf1625b8bcfc4de637d34e94edafcd5add0c72acb6032215b933ffb8e2803322864333464313432386233656661313338336238306263623261653735326632366564613665386239388cc9a8c90642283932386165333630633661616137636636616666386431373136623030343661613631633130666612b2010a0141108ca6a3c906188cc9a8c90622205a6a67344b4873736144585950376233445a446b5341744f627a456b476c7a6c2a5b3059301306072a8648ce3d020106082a8648ce3d03010703420004755093caa518ea29a86ce57ba78addcecbe041770b63690d16b67c92f4726f4790948ba153e23b563e8fcc4463bce2ae46e73d71bfb05d5e2583d00b5e947a2530033a205a6a67344b4873736144585950376233445a446b5341744f627a456b476c7a6c','d34d1428b3efa1383b80bcb2ae752f26eda6e8b9','');
            DELETE FROM sqlite_sequence;
            INSERT INTO sqlite_sequence VALUES('migrations',1);
            INSERT INTO sqlite_sequence VALUES('bundles',1);
            INSERT INTO sqlite_sequence VALUES('ca_journals',2);
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
            COMMIT;`,
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
