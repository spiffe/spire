package sql

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/blang/semver"
)

var (
	migrationDumps = []string{
		// v0 database
		`PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "bundles" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"deleted_at" datetime,"trust_domain" varchar(255) NOT NULL );
INSERT INTO bundles VALUES(1,'2018-08-16 16:27:36.927328934-06:00','2018-08-16 16:27:36.927328934-06:00',NULL,'spiffe://example.org');
INSERT INTO bundles VALUES(2,'2018-08-16 16:27:38.805813068-06:00','2018-08-16 16:27:38.805813068-06:00','2018-08-16 16:27:54.894500348-06:00','spiffe://otherdomain.org');
CREATE TABLE IF NOT EXISTS "ca_certs" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"deleted_at" datetime,"cert" blob NOT NULL,"expiry" datetime NOT NULL,"bundle_id" integer REFERENCES bundles(id) NOT NULL );
INSERT INTO ca_certs VALUES(1,'2018-08-16 16:27:36.928180373-06:00','2018-08-16 16:27:36.928180373-06:00',NULL,X'308201cc30820153a00302010202090093380e1447d2f9ae300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138303531333139333334375a170d3233303531323139333334375a301e310b3009060355040613025553310f300d060355040a0c065350494646453076301006072a8648ce3d020106052b81040022036200045a307e9d2192c48622ce76fce31bb95860d98fcd272fb5b5737cdfe3c5a1cb499aed8ee60812b37d092b80382e2388f467ed3fb431ffafc82d3ad2cbac8a6e330587a1ee2f6d5045b5ed6f8fa5ede96784f255f0702bcbb3f99c9af3ea54af63a35d305b301d0603551d0e0416041487a5f357a2f035acc0f864c454e76ed3ba39c8e8300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630190603551d1104123010860e7370696666653a2f2f6c6f63616c300a06082a8648ce3d0403040367003064023013831ed77a8c0bd8ba164c74876eb2d3d41921bb91a80f69b8b83d01e780032a39b41cd197560bd0a344a74d9529260902305d789bea8c9f705b9e4e1a3d494300c50fb91678407aa0c9703db23fe61118ddacc98b5e88d2e375252613496192a967','2023-05-12 19:33:47+00:00',1);
INSERT INTO ca_certs VALUES(2,'2018-08-16 16:27:36.928667163-06:00','2018-08-16 16:27:36.928667163-06:00',NULL,X'308201ee30820174a003020102020101300a06082a8648ce3d040303301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138303831363232323732365a170d3138303831363233323733365a301e310b3009060355040613025553310f300d060355040a13065350494646453076301006072a8648ce3d020106052b8104002203620004480e2973443e2ac804dcee2f740b3d859c86dbb7e9740c35e33b05572aa6e82c8460946c627c3f7e7f4a25db21a48499e3d451a0a269a06ecbc2d8b1d4d88d10d1566094d4661d6a52f51c799917eaf9972b840f239571048f3257822fb6abf8a38185308182300e0603551d0f0101ff040403020186300f0603551d130101ff040530030101ff301d0603551d0e04160414d419705a3da12ba10463f937172f17e47012f08b301f0603551d2304183016801487a5f357a2f035acc0f864c454e76ed3ba39c8e8301f0603551d110418301686147370696666653a2f2f6578616d706c652e6f7267300a06082a8648ce3d0403030368003065023100f456e4f5adcc1c9d9b092cd500218af3b0c7e561c173ade01aebe792eed4fbeacc514c76a41fa19239afa580e452acef0230704f8f9d3149ebcf9a1cf43416b4d2e26b4d21a1538238280a60eb56156413de91524a042784e92aeea12feae6d6f31d','2018-08-16 23:27:36+00:00',1);
INSERT INTO ca_certs VALUES(3,'2018-08-16 16:27:36.928855556-06:00','2018-08-16 16:27:36.928855556-06:00',NULL,X'3082018f30820116a003020102020100300a06082a8648ce3d040302301e310b3009060355040613025553310f300d060355040a1306535049464645301e170d3138303831363232323732365a170d3138303831363233323733365a30003059301306072a8648ce3d020106082a8648ce3d03010703420004496cef3b0a61159d672625d031e7d99b764324c5edffe81535e6c857928e2ffe6f0abb230ba2e0eee7dea58140659362dd99cda70ada5c8864e66918fdeef027a3633061300c0603551d130101ff04023000301f0603551d23041830168014d419705a3da12ba10463f937172f17e47012f08b30220603551d110101ff0418301686147370696666653a2f2f6578616d706c652e6f7267300c0603551d250101ff04023000300a06082a8648ce3d0403020367003064023042662bc3d47e397f2bde357ffdc0dcc17cd6a488f7d7acf3c2d1c8dc507c2290c8f96d0bb7c3ddf2cb02c43b4ae580cb023013188d5dc26428ce2f5a47bd2341709fd01c1bb68dcf3d9f78bb7fe47d2b3a8a9c4554b77d8ee370ae1e5a3018360be2','2018-08-16 23:27:36+00:00',1);
INSERT INTO ca_certs VALUES(4,'2018-08-16 16:27:38.806210995-06:00','2018-08-16 16:27:38.806210995-06:00','2018-08-16 16:27:54.894171967-06:00',X'308202393082019aa003020102020101300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138303231303030333434355a170d3138303231303031333435355a301e310b3009060355040613025553310f300d060355040a130653504946464530819b301006072a8648ce3d020106052b810400230381860004019ea75eb35cb4a1cd8d94fb6643fbc707e931fbdcfc3007737f46753dea8bc9a6a30634fd7b854269497175f0bfc665392a06bedb8b004c7596f1cd670bf806eb8f00b20b7085b9b720bca6371b7eab3c3cc418c220bea05287053c57ce89692de1ee14b003f5c71fc168644f5cffb78a6f2e43f8142924068b06f4f560e4941526e649a38185308182300e0603551d0f0101ff040403020186300f0603551d130101ff040530030101ff301d0603551d0e04160414f846e36dc7a13bd328d5d3022f532ac690c29ccf301f0603551d2304183016801446ca8ce5f4c8ee7b4637c3873643edeefb05640a301f0603551d110418301686147370696666653a2f2f6578616d706c652e6f7267300a06082a8648ce3d04030403818c00308188024201ceb71e2c3428a80109e9131dc9fc0f4ce8bbadb61fcd0ff87c0feee5baa124778b4cac14209cc8f8134c4b19436da0535122b114960c24b16bca677064b0820e33024201cf153c0fd062b9490de439f052b2432ace2253e4434a812443a42fa16b027818e76d7c4c23544b7d184b91e323695fcb28c1f9c4951575fc4b3bb4d7d74304c855','2018-02-10 01:34:55+00:00',2);
CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"deleted_at" datetime,"spiffe_id" varchar(255),"data_type" varchar(255),"serial_number" varchar(255),"expires_at" datetime );
CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"deleted_at" datetime,"spiffe_id" varchar(255),"type" varchar(255),"value" varchar(255) );
CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"deleted_at" datetime,"entry_id" varchar(255),"spiffe_id" varchar(255),"parent_id" varchar(255),"ttl" integer,"downstream" bool );
CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"deleted_at" datetime,"token" varchar(255),"expiry" bigint );
CREATE TABLE IF NOT EXISTS "selectors" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"deleted_at" datetime,"registered_entry_id" integer,"type" varchar(255),"value" varchar(255) );
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('bundles',2);
INSERT INTO sqlite_sequence VALUES('ca_certs',4);
CREATE INDEX idx_bundles_deleted_at ON "bundles"(deleted_at) ;
CREATE UNIQUE INDEX uix_bundles_trust_domain ON "bundles"(trust_domain) ;
CREATE INDEX idx_ca_certs_deleted_at ON "ca_certs"(deleted_at) ;
CREATE INDEX idx_ca_certs_expiry ON "ca_certs"("expiry") ;
CREATE INDEX idx_ca_certs_bundle_id ON "ca_certs"(bundle_id) ;
CREATE INDEX idx_attested_node_entries_deleted_at ON "attested_node_entries"(deleted_at) ;
CREATE UNIQUE INDEX uix_attested_node_entries_spiffe_id ON "attested_node_entries"(spiffe_id) ;
CREATE INDEX idx_node_resolver_map_entries_deleted_at ON "node_resolver_map_entries"(deleted_at) ;
CREATE UNIQUE INDEX idx_node_resolver_map ON "node_resolver_map_entries"(spiffe_id, "type", "value") ;
CREATE INDEX idx_registered_entries_deleted_at ON "registered_entries"(deleted_at) ;
CREATE UNIQUE INDEX uix_registered_entries_entry_id ON "registered_entries"(entry_id) ;
CREATE INDEX idx_join_tokens_deleted_at ON "join_tokens"(deleted_at) ;
CREATE UNIQUE INDEX uix_join_tokens_token ON "join_tokens"("token") ;
CREATE INDEX idx_selectors_deleted_at ON "selectors"(deleted_at) ;
CREATE UNIQUE INDEX idx_selector_entry ON "selectors"(registered_entry_id, "type", "value") ;
COMMIT;
`,
		// v1 database
		`PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "bundles" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL );
CREATE TABLE IF NOT EXISTS "ca_certs" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"cert" blob NOT NULL,"expiry" datetime NOT NULL,"bundle_id" integer REFERENCES bundles(id) NOT NULL );
CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"data_type" varchar(255),"serial_number" varchar(255),"expires_at" datetime );
CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"type" varchar(255),"value" varchar(255) );
CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255),"spiffe_id" varchar(255),"parent_id" varchar(255),"ttl" integer,"downstream" varchar(255) );
CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"token" varchar(255),"expiry" bigint );
CREATE TABLE IF NOT EXISTS "selectors" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"type" varchar(255),"value" varchar(255) );
CREATE TABLE IF NOT EXISTS "migrations" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"version" integer );
INSERT INTO migrations VALUES(1,'2018-08-21 08:26:19.425200053-06:00','2018-08-21 08:26:19.425200053-06:00',1);
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('migrations',1);
INSERT INTO sqlite_sequence VALUES('bundles',1);
INSERT INTO sqlite_sequence VALUES('ca_certs',3);
CREATE UNIQUE INDEX uix_bundles_trust_domain ON "bundles"(trust_domain) ;
CREATE INDEX idx_ca_certs_expiry ON "ca_certs"("expiry") ;
CREATE INDEX idx_ca_certs_bundle_id ON "ca_certs"(bundle_id) ;
CREATE UNIQUE INDEX uix_attested_node_entries_spiffe_id ON "attested_node_entries"(spiffe_id) ;
CREATE UNIQUE INDEX idx_node_resolver_map ON "node_resolver_map_entries"(spiffe_id, "type", "value") ;
CREATE UNIQUE INDEX uix_registered_entries_entry_id ON "registered_entries"(entry_id) ;
CREATE UNIQUE INDEX uix_join_tokens_token ON "join_tokens"("token") ;
CREATE UNIQUE INDEX idx_selector_entry ON "selectors"(registered_entry_id, "type", "value") ;
COMMIT;
`,
		// v2 database
		`
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "federated_registration_entries" ("bundle_id" integer,"registered_entry_id" integer, PRIMARY KEY ("bundle_id","registered_entry_id"));
INSERT INTO federated_registration_entries VALUES(2,2);
CREATE TABLE IF NOT EXISTS "bundles" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL );
INSERT INTO bundles VALUES(1,'2018-09-25 15:05:01.939161-06:00','2018-09-25 15:05:01.939161-06:00','spiffe://eXAMPLe.org');
INSERT INTO bundles VALUES(2,'2018-09-25 15:06:06.013273-06:00','2018-09-25 15:06:06.013273-06:00','spiffe://othERDOMAin.test');
CREATE TABLE IF NOT EXISTS "ca_certs" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"cert" blob NOT NULL,"expiry" datetime NOT NULL,"bundle_id" integer REFERENCES bundles(id) NOT NULL );
INSERT INTO ca_certs VALUES(1,'2018-09-25 15:05:01.939231-06:00','2018-09-25 15:05:01.939231-06:00',X'308201cc30820153a00302010202090093380e1447d2f9ae300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138303531333139333334375a170d3233303531323139333334375a301e310b3009060355040613025553310f300d060355040a0c065350494646453076301006072a8648ce3d020106052b81040022036200045a307e9d2192c48622ce76fce31bb95860d98fcd272fb5b5737cdfe3c5a1cb499aed8ee60812b37d092b80382e2388f467ed3fb431ffafc82d3ad2cbac8a6e330587a1ee2f6d5045b5ed6f8fa5ede96784f255f0702bcbb3f99c9af3ea54af63a35d305b301d0603551d0e0416041487a5f357a2f035acc0f864c454e76ed3ba39c8e8300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630190603551d1104123010860e7370696666653a2f2f6c6f63616c300a06082a8648ce3d0403040367003064023013831ed77a8c0bd8ba164c74876eb2d3d41921bb91a80f69b8b83d01e780032a39b41cd197560bd0a344a74d9529260902305d789bea8c9f705b9e4e1a3d494300c50fb91678407aa0c9703db23fe61118ddacc98b5e88d2e375252613496192a967','2023-05-12 19:33:47+00:00',1);
INSERT INTO ca_certs VALUES(2,'2018-09-25 15:05:01.939315-06:00','2018-09-25 15:05:01.939315-06:00',X'308201ef30820174a003020102020101300a06082a8648ce3d040303301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138303932353231303435315a170d3138303932353232303530315a301e310b3009060355040613025553310f300d060355040a13065350494646453076301006072a8648ce3d020106052b8104002203620004fd401bfb35167bddb641e6cb7026779ad501be6e829bd4b0b681d67e5986e41f40ec1aeb97727cae37debf679029d49ee17a88d59f36285c4a1b3970b11bf330bb71cf89bc350edddc5d4000ec51d0c5cae55bc4fd51a1f981d74f94f3b7ea77a38185308182300e0603551d0f0101ff040403020186300f0603551d130101ff040530030101ff301d0603551d0e041604148e9cd4389b86b7410ade8b51b39443d59d8c52b4301f0603551d2304183016801487a5f357a2f035acc0f864c454e76ed3ba39c8e8301f0603551d110418301686147370696666653a2f2f6558414d504c652e6f7267300a06082a8648ce3d0403030369003066023100b577d9e8b3309f4b4ee57badfd8e6ff4758285715e3c5e4482f577b0d555ff6de7aeb43c3c5e076cb4cb8d22bb1a9b0e02310099c529677ed979ec790f620278354ef1a4df745bf1d08179d2ce02496ce3a1a553acb8414ab914812a064d82212a1a90','2018-09-25 22:05:01+00:00',1);
INSERT INTO ca_certs VALUES(3,'2018-09-25 15:05:01.939367-06:00','2018-09-25 15:05:01.939367-06:00',X'3082019030820116a003020102020100300a06082a8648ce3d040302301e310b3009060355040613025553310f300d060355040a1306535049464645301e170d3138303932353231303435315a170d3138303932353232303530315a30003059301306072a8648ce3d020106082a8648ce3d03010703420004a09cb3bd6bf27ec2bbba81dc5486eda75e9ce089cdcb04dd678e32a998bda715cfb867ab77e4b44aa96e1d6fa0610e83be16341e52c89a4fc905c79a5bb4c5e1a3633061300c0603551d130101ff04023000301f0603551d230418301680148e9cd4389b86b7410ade8b51b39443d59d8c52b430220603551d110101ff0418301686147370696666653a2f2f6558414d504c652e6f7267300c0603551d250101ff04023000300a06082a8648ce3d040302036800306502310093ef71581e5912e2c90de55399aca10e033463d5a305edcccc3994dcc261d85c8167ce21e7cb93c30c48cd77633c2ef802307a23500af46baa84f002a1f2907d0c416080cb61e708922f2a45e9142544a7b124e631dbdef309673a5dcccb1fff6879','2018-09-25 22:05:01+00:00',1);
INSERT INTO ca_certs VALUES(4,'2018-09-25 15:06:06.013367-06:00','2018-09-25 15:06:06.013367-06:00',X'308202393082019aa003020102020101300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138303231303030333434355a170d3138303231303031333435355a301e310b3009060355040613025553310f300d060355040a130653504946464530819b301006072a8648ce3d020106052b810400230381860004019ea75eb35cb4a1cd8d94fb6643fbc707e931fbdcfc3007737f46753dea8bc9a6a30634fd7b854269497175f0bfc665392a06bedb8b004c7596f1cd670bf806eb8f00b20b7085b9b720bca6371b7eab3c3cc418c220bea05287053c57ce89692de1ee14b003f5c71fc168644f5cffb78a6f2e43f8142924068b06f4f560e4941526e649a38185308182300e0603551d0f0101ff040403020186300f0603551d130101ff040530030101ff301d0603551d0e04160414f846e36dc7a13bd328d5d3022f532ac690c29ccf301f0603551d2304183016801446ca8ce5f4c8ee7b4637c3873643edeefb05640a301f0603551d110418301686147370696666653a2f2f6578616d706c652e6f7267300a06082a8648ce3d04030403818c00308188024201ceb71e2c3428a80109e9131dc9fc0f4ce8bbadb61fcd0ff87c0feee5baa124778b4cac14209cc8f8134c4b19436da0535122b114960c24b16bca677064b0820e33024201cf153c0fd062b9490de439f052b2432ace2253e4434a812443a42fa16b027818e76d7c4c23544b7d184b91e323695fcb28c1f9c4951575fc4b3bb4d7d74304c855','2018-02-10 01:34:55+00:00',2);
CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"data_type" varchar(255),"serial_number" varchar(255),"expires_at" datetime );
INSERT INTO attested_node_entries VALUES(1,'2018-09-25 15:07:02.267049-06:00','2018-09-25 15:07:02.267049-06:00','spiffe://eXAMPLe.org/spire/agent/join_token/13f1db93-6018-4496-8e77-6de440a174ed','join_token','2','2018-09-25 16:05:01-06:00');
CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"type" varchar(255),"value" varchar(255) );
INSERT INTO node_resolver_map_entries VALUES(1, '2018-09-25 15:07:02.267049-06:00', '2018-09-25 15:07:02.267049-06:00', 'spiffe://eXAMPLe.org/spire/agent/join_token/13f1db93-6018-4496-8e77-6de440a174ed', 'foo', 'bar');
CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255),"spiffe_id" varchar(255),"parent_id" varchar(255),"ttl" integer, "downstream" varchar(255));
INSERT INTO registered_entries VALUES(1,'2018-09-25 15:06:15.092674-06:00','2018-09-25 15:06:15.092674-06:00','00000000-0000-0000-0000-000000000001','spiffe://eXAMPLe.org/nODe','spiffe://eXAMPLe.org/spire/agent/join_token/13f1db93-6018-4496-8e77-6de440a174ed',0,false);
INSERT INTO registered_entries VALUES(2,'2018-09-25 15:06:49.602113-06:00','2018-09-25 15:06:49.602113-06:00','00000000-0000-0000-0000-000000000002','spiffe://eXAMPLe.org/bLOg','spiffe://eXAMPLe.org/nODe',3600,false);
CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"token" varchar(255),"expiry" bigint );
CREATE TABLE IF NOT EXISTS "selectors" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"type" varchar(255),"value" varchar(255) );
INSERT INTO selectors VALUES(1,'2018-09-25 15:06:15.092823-06:00','2018-09-25 15:06:15.092823-06:00',1,'spiffe_id','spiffe://eXAMPLe.org/spire/agent/join_token/13f1db93-6018-4496-8e77-6de440a174ed');
INSERT INTO selectors VALUES(2,'2018-09-25 15:06:49.602485-06:00','2018-09-25 15:06:49.602485-06:00',2,'unix','uid:0');
CREATE TABLE IF NOT EXISTS "migrations" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"version" integer );
INSERT INTO migrations VALUES(1,'2018-09-25 15:05:01.891816-06:00','2018-09-25 15:05:01.891816-06:00',2);
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('migrations',1);
INSERT INTO sqlite_sequence VALUES('bundles',2);
INSERT INTO sqlite_sequence VALUES('ca_certs',4);
INSERT INTO sqlite_sequence VALUES('join_tokens',1);
INSERT INTO sqlite_sequence VALUES('registered_entries',2);
INSERT INTO sqlite_sequence VALUES('selectors',2);
INSERT INTO sqlite_sequence VALUES('attested_node_entries',1);
CREATE UNIQUE INDEX uix_bundles_trust_domain ON "bundles"(trust_domain) ;
CREATE INDEX idx_ca_certs_expiry ON "ca_certs"("expiry") ;
CREATE INDEX idx_ca_certs_bundle_id ON "ca_certs"(bundle_id) ;
CREATE UNIQUE INDEX uix_attested_node_entries_spiffe_id ON "attested_node_entries"(spiffe_id) ;
CREATE UNIQUE INDEX idx_node_resolver_map ON "node_resolver_map_entries"(spiffe_id, "type", "value") ;
CREATE UNIQUE INDEX uix_registered_entries_entry_id ON "registered_entries"(entry_id) ;
CREATE UNIQUE INDEX uix_join_tokens_token ON "join_tokens"("token") ;
CREATE UNIQUE INDEX idx_selector_entry ON "selectors"(registered_entry_id, "type", "value") ;
COMMIT;
`,
		// v3 database
		`
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "federated_registration_entries" ("bundle_id" integer,"registered_entry_id" integer, PRIMARY KEY ("bundle_id","registered_entry_id"));
INSERT INTO federated_registration_entries VALUES(2,2);
CREATE TABLE IF NOT EXISTS "bundles" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL );
INSERT INTO bundles VALUES(1,'2018-09-25 15:05:01.939161-06:00','2018-09-25 15:05:01.939161-06:00','spiffe://example.org');
INSERT INTO bundles VALUES(2,'2018-09-25 15:06:06.013273-06:00','2018-09-25 15:06:06.013273-06:00','spiffe://otherdomain.test');
CREATE TABLE IF NOT EXISTS "ca_certs" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"cert" blob NOT NULL,"expiry" datetime NOT NULL,"bundle_id" integer REFERENCES bundles(id) NOT NULL );
INSERT INTO ca_certs VALUES(1,'2018-09-25 15:05:01.939231-06:00','2018-09-25 15:05:01.939231-06:00',X'308201cc30820153a00302010202090093380e1447d2f9ae300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138303531333139333334375a170d3233303531323139333334375a301e310b3009060355040613025553310f300d060355040a0c065350494646453076301006072a8648ce3d020106052b81040022036200045a307e9d2192c48622ce76fce31bb95860d98fcd272fb5b5737cdfe3c5a1cb499aed8ee60812b37d092b80382e2388f467ed3fb431ffafc82d3ad2cbac8a6e330587a1ee2f6d5045b5ed6f8fa5ede96784f255f0702bcbb3f99c9af3ea54af63a35d305b301d0603551d0e0416041487a5f357a2f035acc0f864c454e76ed3ba39c8e8300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630190603551d1104123010860e7370696666653a2f2f6c6f63616c300a06082a8648ce3d0403040367003064023013831ed77a8c0bd8ba164c74876eb2d3d41921bb91a80f69b8b83d01e780032a39b41cd197560bd0a344a74d9529260902305d789bea8c9f705b9e4e1a3d494300c50fb91678407aa0c9703db23fe61118ddacc98b5e88d2e375252613496192a967','2023-05-12 19:33:47+00:00',1);
INSERT INTO ca_certs VALUES(2,'2018-09-25 15:05:01.939315-06:00','2018-09-25 15:05:01.939315-06:00',X'308201ef30820174a003020102020101300a06082a8648ce3d040303301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138303932353231303435315a170d3138303932353232303530315a301e310b3009060355040613025553310f300d060355040a13065350494646453076301006072a8648ce3d020106052b8104002203620004fd401bfb35167bddb641e6cb7026779ad501be6e829bd4b0b681d67e5986e41f40ec1aeb97727cae37debf679029d49ee17a88d59f36285c4a1b3970b11bf330bb71cf89bc350edddc5d4000ec51d0c5cae55bc4fd51a1f981d74f94f3b7ea77a38185308182300e0603551d0f0101ff040403020186300f0603551d130101ff040530030101ff301d0603551d0e041604148e9cd4389b86b7410ade8b51b39443d59d8c52b4301f0603551d2304183016801487a5f357a2f035acc0f864c454e76ed3ba39c8e8301f0603551d110418301686147370696666653a2f2f6558414d504c652e6f7267300a06082a8648ce3d0403030369003066023100b577d9e8b3309f4b4ee57badfd8e6ff4758285715e3c5e4482f577b0d555ff6de7aeb43c3c5e076cb4cb8d22bb1a9b0e02310099c529677ed979ec790f620278354ef1a4df745bf1d08179d2ce02496ce3a1a553acb8414ab914812a064d82212a1a90','2018-09-25 22:05:01+00:00',1);
INSERT INTO ca_certs VALUES(3,'2018-09-25 15:05:01.939367-06:00','2018-09-25 15:05:01.939367-06:00',X'3082019030820116a003020102020100300a06082a8648ce3d040302301e310b3009060355040613025553310f300d060355040a1306535049464645301e170d3138303932353231303435315a170d3138303932353232303530315a30003059301306072a8648ce3d020106082a8648ce3d03010703420004a09cb3bd6bf27ec2bbba81dc5486eda75e9ce089cdcb04dd678e32a998bda715cfb867ab77e4b44aa96e1d6fa0610e83be16341e52c89a4fc905c79a5bb4c5e1a3633061300c0603551d130101ff04023000301f0603551d230418301680148e9cd4389b86b7410ade8b51b39443d59d8c52b430220603551d110101ff0418301686147370696666653a2f2f6558414d504c652e6f7267300c0603551d250101ff04023000300a06082a8648ce3d040302036800306502310093ef71581e5912e2c90de55399aca10e033463d5a305edcccc3994dcc261d85c8167ce21e7cb93c30c48cd77633c2ef802307a23500af46baa84f002a1f2907d0c416080cb61e708922f2a45e9142544a7b124e631dbdef309673a5dcccb1fff6879','2018-09-25 22:05:01+00:00',1);
INSERT INTO ca_certs VALUES(4,'2018-09-25 15:06:06.013367-06:00','2018-09-25 15:06:06.013367-06:00',X'308202393082019aa003020102020101300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138303231303030333434355a170d3138303231303031333435355a301e310b3009060355040613025553310f300d060355040a130653504946464530819b301006072a8648ce3d020106052b810400230381860004019ea75eb35cb4a1cd8d94fb6643fbc707e931fbdcfc3007737f46753dea8bc9a6a30634fd7b854269497175f0bfc665392a06bedb8b004c7596f1cd670bf806eb8f00b20b7085b9b720bca6371b7eab3c3cc418c220bea05287053c57ce89692de1ee14b003f5c71fc168644f5cffb78a6f2e43f8142924068b06f4f560e4941526e649a38185308182300e0603551d0f0101ff040403020186300f0603551d130101ff040530030101ff301d0603551d0e04160414f846e36dc7a13bd328d5d3022f532ac690c29ccf301f0603551d2304183016801446ca8ce5f4c8ee7b4637c3873643edeefb05640a301f0603551d110418301686147370696666653a2f2f6578616d706c652e6f7267300a06082a8648ce3d04030403818c00308188024201ceb71e2c3428a80109e9131dc9fc0f4ce8bbadb61fcd0ff87c0feee5baa124778b4cac14209cc8f8134c4b19436da0535122b114960c24b16bca677064b0820e33024201cf153c0fd062b9490de439f052b2432ace2253e4434a812443a42fa16b027818e76d7c4c23544b7d184b91e323695fcb28c1f9c4951575fc4b3bb4d7d74304c855','2018-02-10 01:34:55+00:00',2);
CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"data_type" varchar(255),"serial_number" varchar(255),"expires_at" datetime );
INSERT INTO attested_node_entries VALUES(1,'2018-09-25 15:07:02.267049-06:00','2018-09-25 15:07:02.267049-06:00','spiffe://example.org/spire/agent/join_token/13f1db93-6018-4496-8e77-6de440a174ed','join_token','2','2018-09-25 16:05:01-06:00');
CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"type" varchar(255),"value" varchar(255) );
INSERT INTO node_resolver_map_entries VALUES(1, '2018-09-25 15:07:02.267049-06:00', '2018-09-25 15:07:02.267049-06:00', 'spiffe://example.org/spire/agent/join_token/13f1db93-6018-4496-8e77-6de440a174ed', 'foo', 'bar');
CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255),"spiffe_id" varchar(255),"parent_id" varchar(255),"ttl" integer,"downstream" bool);
INSERT INTO registered_entries VALUES(1,'2018-09-25 15:06:15.092674-06:00','2018-09-25 15:06:15.092674-06:00','00000000-0000-0000-0000-000000000001','spiffe://example.org/nODe','spiffe://example.org/spire/agent/join_token/13f1db93-6018-4496-8e77-6de440a174ed',0,true);
INSERT INTO registered_entries VALUES(2,'2018-09-25 15:06:49.602113-06:00','2018-09-25 15:06:49.602113-06:00','00000000-0000-0000-0000-000000000002','spiffe://example.org/bLOg','spiffe://example.org/nODe',3600,true);
CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"token" varchar(255),"expiry" bigint );
CREATE TABLE IF NOT EXISTS "selectors" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"type" varchar(255),"value" varchar(255) );
INSERT INTO selectors VALUES(1,'2018-09-25 15:06:15.092823-06:00','2018-09-25 15:06:15.092823-06:00',1,'spiffe_id','spiffe://example.org/spire/agent/join_token/13f1db93-6018-4496-8e77-6de440a174ed');
INSERT INTO selectors VALUES(2,'2018-09-25 15:06:49.602485-06:00','2018-09-25 15:06:49.602485-06:00',2,'unix','uid:0');
CREATE TABLE IF NOT EXISTS "migrations" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"version" integer );
INSERT INTO migrations VALUES(1,'2018-09-25 15:05:01.891816-06:00','2018-09-25 15:05:01.891816-06:00',2);
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('migrations',1);
INSERT INTO sqlite_sequence VALUES('bundles',2);
INSERT INTO sqlite_sequence VALUES('ca_certs',4);
INSERT INTO sqlite_sequence VALUES('join_tokens',1);
INSERT INTO sqlite_sequence VALUES('registered_entries',2);
INSERT INTO sqlite_sequence VALUES('selectors',2);
INSERT INTO sqlite_sequence VALUES('attested_node_entries',1);
CREATE UNIQUE INDEX uix_bundles_trust_domain ON "bundles"(trust_domain) ;
CREATE INDEX idx_ca_certs_expiry ON "ca_certs"("expiry") ;
CREATE INDEX idx_ca_certs_bundle_id ON "ca_certs"(bundle_id) ;
CREATE UNIQUE INDEX uix_attested_node_entries_spiffe_id ON "attested_node_entries"(spiffe_id) ;
CREATE UNIQUE INDEX idx_node_resolver_map ON "node_resolver_map_entries"(spiffe_id, "type", "value") ;
CREATE UNIQUE INDEX uix_registered_entries_entry_id ON "registered_entries"(entry_id) ;
CREATE UNIQUE INDEX uix_join_tokens_token ON "join_tokens"("token") ;
CREATE UNIQUE INDEX idx_selector_entry ON "selectors"(registered_entry_id, "type", "value") ;
COMMIT;
`,
		// v4 database
		`
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "federated_registration_entries" ("bundle_id" integer,"registered_entry_id" integer, PRIMARY KEY ("bundle_id","registered_entry_id"));
CREATE TABLE IF NOT EXISTS "bundles" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"data" blob );
INSERT INTO bundles VALUES(1,'2018-12-19 14:26:32.340488-07:00','2018-12-19 14:26:32.340488-07:00','spiffe://example.org',X'0a147370696666653a2f2f6578616d706c652e6f726712f6030af303308201ef30820174a003020102020101300a06082a8648ce3d040303301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138313231393231323632325a170d3138313231393232323633325a301e310b3009060355040613025553310f300d060355040a13065350494646453076301006072a8648ce3d020106052b8104002203620004c941f4fdc386a57aa74807d64a05fdedac4d3c9cd0841beac744db4163ae6ba46e883551c683cf11781c8958ebb11ae9a4bbeb3bbf751aaa9e645e65ab6ee3c5b681621d538929956f37e182c8f955614bef67e7921b3371571b87a0065e0f8da38185308182300e0603551d0f0101ff040403020186300f0603551d130101ff040530030101ff301d0603551d0e04160414bb9e6ee33abb3b2d2587b5c67f66f74851487739301f0603551d2304183016801487a5f357a2f035acc0f864c454e76ed3ba39c8e8301f0603551d110418301686147370696666653a2f2f6578616d706c652e6f7267300a06082a8648ce3d0403030369003066023100813cc8650728e10cdfd5230d484dd4353ec7513dc2543cb51c1115dfb62d5d1ca92dd586137d273b4ad6a78a53dedc6c023100d16f9478064213f3e6fbe9cd3a96dd730caa413464fadaf634337e810d5e6be7da15d7c142d309cb76fd0f6f5cf111e112d3030ad003308201cc30820153a00302010202090093380e1447d2f9ae300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138303531333139333334375a170d3233303531323139333334375a301e310b3009060355040613025553310f300d060355040a0c065350494646453076301006072a8648ce3d020106052b81040022036200045a307e9d2192c48622ce76fce31bb95860d98fcd272fb5b5737cdfe3c5a1cb499aed8ee60812b37d092b80382e2388f467ed3fb431ffafc82d3ad2cbac8a6e330587a1ee2f6d5045b5ed6f8fa5ede96784f255f0702bcbb3f99c9af3ea54af63a35d305b301d0603551d0e0416041487a5f357a2f035acc0f864c454e76ed3ba39c8e8300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630190603551d1104123010860e7370696666653a2f2f6c6f63616c300a06082a8648ce3d0403040367003064023013831ed77a8c0bd8ba164c74876eb2d3d41921bb91a80f69b8b83d01e780032a39b41cd197560bd0a344a74d9529260902305d789bea8c9f705b9e4e1a3d494300c50fb91678407aa0c9703db23fe61118ddacc98b5e88d2e375252613496192a9671a85010a5b3059301306072a8648ce3d020106082a8648ce3d030107034200041db49815c4dc0a343e25ba73a2f6add69a034f968f9319c34eb6ef89c2674c92a310ebcef9d393fb478c7f00ce4a1dd0926b54cf6bbae5544968cd933b1372f61220486558424e674565324b6d744b563143384738674b5450766c59536c4156675318988bebe005');
CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"data_type" varchar(255),"serial_number" varchar(255),"expires_at" datetime );
CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"type" varchar(255),"value" varchar(255) );
CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255),"spiffe_id" varchar(255),"parent_id" varchar(255),"ttl" integer );
INSERT INTO registered_entries VALUES(1,'2018-12-19 14:26:58.227869-07:00','2018-12-19 14:26:58.227869-07:00','f0373f87-a0f3-4c94-aa6a-a2f948bfc15a','spiffe://example.org/admin','spiffe://example.org/spire/agent/x509pop/e81aef2e9178db3db836a1a85d362ca5b2241631',3600);
CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"token" varchar(255),"expiry" bigint );
CREATE TABLE IF NOT EXISTS "selectors" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"type" varchar(255),"value" varchar(255) );
INSERT INTO selectors VALUES(1,'2018-12-19 14:26:58.228067-07:00','2018-12-19 14:26:58.228067-07:00',1,'unix','uid:501');
CREATE TABLE IF NOT EXISTS "migrations" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"version" integer );
INSERT INTO migrations VALUES(1,'2018-12-19 14:26:32.297244-07:00','2018-12-19 14:26:32.297244-07:00',4);
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('migrations',1);
INSERT INTO sqlite_sequence VALUES('bundles',1);
INSERT INTO sqlite_sequence VALUES('registered_entries',1);
INSERT INTO sqlite_sequence VALUES('selectors',1);
CREATE UNIQUE INDEX uix_bundles_trust_domain ON "bundles"(trust_domain) ;
CREATE UNIQUE INDEX uix_attested_node_entries_spiffe_id ON "attested_node_entries"(spiffe_id) ;
CREATE UNIQUE INDEX idx_node_resolver_map ON "node_resolver_map_entries"(spiffe_id, "type", "value") ;
CREATE UNIQUE INDEX uix_registered_entries_entry_id ON "registered_entries"(entry_id) ;
CREATE UNIQUE INDEX uix_join_tokens_token ON "join_tokens"("token") ;
CREATE UNIQUE INDEX idx_selector_entry ON "selectors"(registered_entry_id, "type", "value") ;
COMMIT;
`,
		// v5 database
		`
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "federated_registration_entries" ("bundle_id" integer,"registered_entry_id" integer, PRIMARY KEY ("bundle_id","registered_entry_id"));
CREATE TABLE IF NOT EXISTS "bundles" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"data" blob );
INSERT INTO bundles VALUES(1,'2018-12-19 14:26:32.340488-07:00','2018-12-19 14:26:32.340488-07:00','spiffe://example.org',X'0a147370696666653a2f2f6578616d706c652e6f726712f6030af303308201ef30820174a003020102020101300a06082a8648ce3d040303301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138313231393231323632325a170d3138313231393232323633325a301e310b3009060355040613025553310f300d060355040a13065350494646453076301006072a8648ce3d020106052b8104002203620004c941f4fdc386a57aa74807d64a05fdedac4d3c9cd0841beac744db4163ae6ba46e883551c683cf11781c8958ebb11ae9a4bbeb3bbf751aaa9e645e65ab6ee3c5b681621d538929956f37e182c8f955614bef67e7921b3371571b87a0065e0f8da38185308182300e0603551d0f0101ff040403020186300f0603551d130101ff040530030101ff301d0603551d0e04160414bb9e6ee33abb3b2d2587b5c67f66f74851487739301f0603551d2304183016801487a5f357a2f035acc0f864c454e76ed3ba39c8e8301f0603551d110418301686147370696666653a2f2f6578616d706c652e6f7267300a06082a8648ce3d0403030369003066023100813cc8650728e10cdfd5230d484dd4353ec7513dc2543cb51c1115dfb62d5d1ca92dd586137d273b4ad6a78a53dedc6c023100d16f9478064213f3e6fbe9cd3a96dd730caa413464fadaf634337e810d5e6be7da15d7c142d309cb76fd0f6f5cf111e112d3030ad003308201cc30820153a00302010202090093380e1447d2f9ae300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138303531333139333334375a170d3233303531323139333334375a301e310b3009060355040613025553310f300d060355040a0c065350494646453076301006072a8648ce3d020106052b81040022036200045a307e9d2192c48622ce76fce31bb95860d98fcd272fb5b5737cdfe3c5a1cb499aed8ee60812b37d092b80382e2388f467ed3fb431ffafc82d3ad2cbac8a6e330587a1ee2f6d5045b5ed6f8fa5ede96784f255f0702bcbb3f99c9af3ea54af63a35d305b301d0603551d0e0416041487a5f357a2f035acc0f864c454e76ed3ba39c8e8300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630190603551d1104123010860e7370696666653a2f2f6c6f63616c300a06082a8648ce3d0403040367003064023013831ed77a8c0bd8ba164c74876eb2d3d41921bb91a80f69b8b83d01e780032a39b41cd197560bd0a344a74d9529260902305d789bea8c9f705b9e4e1a3d494300c50fb91678407aa0c9703db23fe61118ddacc98b5e88d2e375252613496192a9671a85010a5b3059301306072a8648ce3d020106082a8648ce3d030107034200041db49815c4dc0a343e25ba73a2f6add69a034f968f9319c34eb6ef89c2674c92a310ebcef9d393fb478c7f00ce4a1dd0926b54cf6bbae5544968cd933b1372f61220486558424e674565324b6d744b563143384738674b5450766c59536c4156675318988bebe005');
CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"data_type" varchar(255),"serial_number" varchar(255),"expires_at" datetime );
CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"type" varchar(255),"value" varchar(255) );
CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255),"spiffe_id" varchar(255),"parent_id" varchar(255),"ttl" integer, "admin" bool);
INSERT INTO registered_entries VALUES(1,'2018-12-19 14:26:58.227869-07:00','2018-12-19 14:26:58.227869-07:00','f0373f87-a0f3-4c94-aa6a-a2f948bfc15a','spiffe://example.org/admin','spiffe://example.org/spire/agent/x509pop/e81aef2e9178db3db836a1a85d362ca5b2241631',3600, 0);
CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"token" varchar(255),"expiry" bigint );
CREATE TABLE IF NOT EXISTS "selectors" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"type" varchar(255),"value" varchar(255) );
INSERT INTO selectors VALUES(1,'2018-12-19 14:26:58.228067-07:00','2018-12-19 14:26:58.228067-07:00',1,'unix','uid:501');
CREATE TABLE IF NOT EXISTS "migrations" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"version" integer );
INSERT INTO migrations VALUES(1,'2018-12-19 14:26:32.297244-07:00','2018-12-19 14:26:32.297244-07:00',5);
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('migrations',1);
INSERT INTO sqlite_sequence VALUES('bundles',1);
INSERT INTO sqlite_sequence VALUES('registered_entries',1);
INSERT INTO sqlite_sequence VALUES('selectors',1);
CREATE UNIQUE INDEX uix_bundles_trust_domain ON "bundles"(trust_domain) ;
CREATE UNIQUE INDEX uix_attested_node_entries_spiffe_id ON "attested_node_entries"(spiffe_id) ;
CREATE UNIQUE INDEX idx_node_resolver_map ON "node_resolver_map_entries"(spiffe_id, "type", "value") ;
CREATE UNIQUE INDEX uix_registered_entries_entry_id ON "registered_entries"(entry_id) ;
CREATE UNIQUE INDEX uix_join_tokens_token ON "join_tokens"("token") ;
CREATE UNIQUE INDEX idx_selector_entry ON "selectors"(registered_entry_id, "type", "value") ;
COMMIT;
`,
		// v6 database
		`
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "federated_registration_entries" ("bundle_id" integer,"registered_entry_id" integer, PRIMARY KEY ("bundle_id","registered_entry_id"));
CREATE TABLE IF NOT EXISTS "bundles" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"data" blob );
INSERT INTO bundles VALUES(1,'2018-12-19 14:26:32.340488-07:00','2018-12-19 14:26:32.340488-07:00','spiffe://example.org',X'0a147370696666653a2f2f6578616d706c652e6f726712f6030af303308201ef30820174a003020102020101300a06082a8648ce3d040303301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138313231393231323632325a170d3138313231393232323633325a301e310b3009060355040613025553310f300d060355040a13065350494646453076301006072a8648ce3d020106052b8104002203620004c941f4fdc386a57aa74807d64a05fdedac4d3c9cd0841beac744db4163ae6ba46e883551c683cf11781c8958ebb11ae9a4bbeb3bbf751aaa9e645e65ab6ee3c5b681621d538929956f37e182c8f955614bef67e7921b3371571b87a0065e0f8da38185308182300e0603551d0f0101ff040403020186300f0603551d130101ff040530030101ff301d0603551d0e04160414bb9e6ee33abb3b2d2587b5c67f66f74851487739301f0603551d2304183016801487a5f357a2f035acc0f864c454e76ed3ba39c8e8301f0603551d110418301686147370696666653a2f2f6578616d706c652e6f7267300a06082a8648ce3d0403030369003066023100813cc8650728e10cdfd5230d484dd4353ec7513dc2543cb51c1115dfb62d5d1ca92dd586137d273b4ad6a78a53dedc6c023100d16f9478064213f3e6fbe9cd3a96dd730caa413464fadaf634337e810d5e6be7da15d7c142d309cb76fd0f6f5cf111e112d3030ad003308201cc30820153a00302010202090093380e1447d2f9ae300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138303531333139333334375a170d3233303531323139333334375a301e310b3009060355040613025553310f300d060355040a0c065350494646453076301006072a8648ce3d020106052b81040022036200045a307e9d2192c48622ce76fce31bb95860d98fcd272fb5b5737cdfe3c5a1cb499aed8ee60812b37d092b80382e2388f467ed3fb431ffafc82d3ad2cbac8a6e330587a1ee2f6d5045b5ed6f8fa5ede96784f255f0702bcbb3f99c9af3ea54af63a35d305b301d0603551d0e0416041487a5f357a2f035acc0f864c454e76ed3ba39c8e8300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630190603551d1104123010860e7370696666653a2f2f6c6f63616c300a06082a8648ce3d0403040367003064023013831ed77a8c0bd8ba164c74876eb2d3d41921bb91a80f69b8b83d01e780032a39b41cd197560bd0a344a74d9529260902305d789bea8c9f705b9e4e1a3d494300c50fb91678407aa0c9703db23fe61118ddacc98b5e88d2e375252613496192a9671a85010a5b3059301306072a8648ce3d020106082a8648ce3d030107034200041db49815c4dc0a343e25ba73a2f6add69a034f968f9319c34eb6ef89c2674c92a310ebcef9d393fb478c7f00ce4a1dd0926b54cf6bbae5544968cd933b1372f61220486558424e674565324b6d744b563143384738674b5450766c59536c4156675318988bebe005');
CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"data_type" varchar(255),"serial_number" varchar(255),"expires_at" datetime );
CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"type" varchar(255),"value" varchar(255) );
CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255),"spiffe_id" varchar(255),"parent_id" varchar(255),"ttl" integer, "admin" bool, "downstream" bool);
INSERT INTO registered_entries VALUES(1,'2018-12-19 14:26:58.227869-07:00','2018-12-19 14:26:58.227869-07:00','f0373f87-a0f3-4c94-aa6a-a2f948bfc15a','spiffe://example.org/admin','spiffe://example.org/spire/agent/x509pop/e81aef2e9178db3db836a1a85d362ca5b2241631',3600, 0, 0);
CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"token" varchar(255),"expiry" bigint );
CREATE TABLE IF NOT EXISTS "selectors" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"type" varchar(255),"value" varchar(255) );
INSERT INTO selectors VALUES(1,'2018-12-19 14:26:58.228067-07:00','2018-12-19 14:26:58.228067-07:00',1,'unix','uid:501');
CREATE TABLE IF NOT EXISTS "migrations" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"version" integer );
INSERT INTO migrations VALUES(1,'2018-12-19 14:26:32.297244-07:00','2018-12-19 14:26:32.297244-07:00',6);
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('migrations',1);
INSERT INTO sqlite_sequence VALUES('bundles',1);
INSERT INTO sqlite_sequence VALUES('registered_entries',1);
INSERT INTO sqlite_sequence VALUES('selectors',1);
CREATE UNIQUE INDEX uix_bundles_trust_domain ON "bundles"(trust_domain) ;
CREATE UNIQUE INDEX uix_attested_node_entries_spiffe_id ON "attested_node_entries"(spiffe_id) ;
CREATE UNIQUE INDEX idx_node_resolver_map ON "node_resolver_map_entries"(spiffe_id, "type", "value") ;
CREATE UNIQUE INDEX uix_registered_entries_entry_id ON "registered_entries"(entry_id) ;
CREATE UNIQUE INDEX uix_join_tokens_token ON "join_tokens"("token") ;
CREATE UNIQUE INDEX idx_selector_entry ON "selectors"(registered_entry_id, "type", "value") ;
COMMIT;
`,
		// v7 database, in which Expiry was added to RegistrationEntry
		`
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "federated_registration_entries" ("bundle_id" integer,"registered_entry_id" integer, PRIMARY KEY ("bundle_id","registered_entry_id"));
CREATE TABLE IF NOT EXISTS "bundles" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"data" blob );
INSERT INTO bundles VALUES(1,'2018-12-19 14:26:32.340488-07:00','2018-12-19 14:26:32.340488-07:00','spiffe://example.org',X'0a147370696666653a2f2f6578616d706c652e6f726712f6030af303308201ef30820174a003020102020101300a06082a8648ce3d040303301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138313231393231323632325a170d3138313231393232323633325a301e310b3009060355040613025553310f300d060355040a13065350494646453076301006072a8648ce3d020106052b8104002203620004c941f4fdc386a57aa74807d64a05fdedac4d3c9cd0841beac744db4163ae6ba46e883551c683cf11781c8958ebb11ae9a4bbeb3bbf751aaa9e645e65ab6ee3c5b681621d538929956f37e182c8f955614bef67e7921b3371571b87a0065e0f8da38185308182300e0603551d0f0101ff040403020186300f0603551d130101ff040530030101ff301d0603551d0e04160414bb9e6ee33abb3b2d2587b5c67f66f74851487739301f0603551d2304183016801487a5f357a2f035acc0f864c454e76ed3ba39c8e8301f0603551d110418301686147370696666653a2f2f6578616d706c652e6f7267300a06082a8648ce3d0403030369003066023100813cc8650728e10cdfd5230d484dd4353ec7513dc2543cb51c1115dfb62d5d1ca92dd586137d273b4ad6a78a53dedc6c023100d16f9478064213f3e6fbe9cd3a96dd730caa413464fadaf634337e810d5e6be7da15d7c142d309cb76fd0f6f5cf111e112d3030ad003308201cc30820153a00302010202090093380e1447d2f9ae300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138303531333139333334375a170d3233303531323139333334375a301e310b3009060355040613025553310f300d060355040a0c065350494646453076301006072a8648ce3d020106052b81040022036200045a307e9d2192c48622ce76fce31bb95860d98fcd272fb5b5737cdfe3c5a1cb499aed8ee60812b37d092b80382e2388f467ed3fb431ffafc82d3ad2cbac8a6e330587a1ee2f6d5045b5ed6f8fa5ede96784f255f0702bcbb3f99c9af3ea54af63a35d305b301d0603551d0e0416041487a5f357a2f035acc0f864c454e76ed3ba39c8e8300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630190603551d1104123010860e7370696666653a2f2f6c6f63616c300a06082a8648ce3d0403040367003064023013831ed77a8c0bd8ba164c74876eb2d3d41921bb91a80f69b8b83d01e780032a39b41cd197560bd0a344a74d9529260902305d789bea8c9f705b9e4e1a3d494300c50fb91678407aa0c9703db23fe61118ddacc98b5e88d2e375252613496192a9671a85010a5b3059301306072a8648ce3d020106082a8648ce3d030107034200041db49815c4dc0a343e25ba73a2f6add69a034f968f9319c34eb6ef89c2674c92a310ebcef9d393fb478c7f00ce4a1dd0926b54cf6bbae5544968cd933b1372f61220486558424e674565324b6d744b563143384738674b5450766c59536c4156675318988bebe005');
CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"data_type" varchar(255),"serial_number" varchar(255),"expires_at" datetime );
CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"type" varchar(255),"value" varchar(255) );
CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255),"spiffe_id" varchar(255),"parent_id" varchar(255),"ttl" integer, "admin" bool, "downstream" bool, "expiry" bigint);
INSERT INTO registered_entries VALUES(1,'2018-12-19 14:26:58.227869-07:00','2018-12-19 14:26:58.227869-07:00','f0373f87-a0f3-4c94-aa6a-a2f948bfc15a','spiffe://example.org/admin','spiffe://example.org/spire/agent/x509pop/e81aef2e9178db3db836a1a85d362ca5b2241631',3600, 0, 0, 0);
CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"token" varchar(255),"expiry" bigint );
CREATE TABLE IF NOT EXISTS "selectors" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"type" varchar(255),"value" varchar(255) );
INSERT INTO selectors VALUES(1,'2018-12-19 14:26:58.228067-07:00','2018-12-19 14:26:58.228067-07:00',1,'unix','uid:501');
CREATE TABLE IF NOT EXISTS "migrations" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"version" integer );
INSERT INTO migrations VALUES(1,'2018-12-19 14:26:32.297244-07:00','2018-12-19 14:26:32.297244-07:00',7);
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('migrations',1);
INSERT INTO sqlite_sequence VALUES('bundles',1);
INSERT INTO sqlite_sequence VALUES('registered_entries',1);
INSERT INTO sqlite_sequence VALUES('selectors',1);
CREATE UNIQUE INDEX uix_bundles_trust_domain ON "bundles"(trust_domain) ;
CREATE UNIQUE INDEX uix_attested_node_entries_spiffe_id ON "attested_node_entries"(spiffe_id) ;
CREATE UNIQUE INDEX idx_node_resolver_map ON "node_resolver_map_entries"(spiffe_id, "type", "value") ;
CREATE UNIQUE INDEX uix_registered_entries_entry_id ON "registered_entries"(entry_id) ;
CREATE UNIQUE INDEX uix_join_tokens_token ON "join_tokens"("token") ;
CREATE UNIQUE INDEX idx_selector_entry ON "selectors"(registered_entry_id, "type", "value") ;
COMMIT;
`,
		// v8 database entry, in which DNSName was added to RegistrationEntry as another table
		`
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "federated_registration_entries" ("bundle_id" integer,"registered_entry_id" integer, PRIMARY KEY ("bundle_id","registered_entry_id"));
CREATE TABLE IF NOT EXISTS "bundles" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"data" blob );
INSERT INTO bundles VALUES(1,'2018-12-19 14:26:32.340488-07:00','2018-12-19 14:26:32.340488-07:00','spiffe://example.org',X'0a147370696666653a2f2f6578616d706c652e6f726712f6030af303308201ef30820174a003020102020101300a06082a8648ce3d040303301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138313231393231323632325a170d3138313231393232323633325a301e310b3009060355040613025553310f300d060355040a13065350494646453076301006072a8648ce3d020106052b8104002203620004c941f4fdc386a57aa74807d64a05fdedac4d3c9cd0841beac744db4163ae6ba46e883551c683cf11781c8958ebb11ae9a4bbeb3bbf751aaa9e645e65ab6ee3c5b681621d538929956f37e182c8f955614bef67e7921b3371571b87a0065e0f8da38185308182300e0603551d0f0101ff040403020186300f0603551d130101ff040530030101ff301d0603551d0e04160414bb9e6ee33abb3b2d2587b5c67f66f74851487739301f0603551d2304183016801487a5f357a2f035acc0f864c454e76ed3ba39c8e8301f0603551d110418301686147370696666653a2f2f6578616d706c652e6f7267300a06082a8648ce3d0403030369003066023100813cc8650728e10cdfd5230d484dd4353ec7513dc2543cb51c1115dfb62d5d1ca92dd586137d273b4ad6a78a53dedc6c023100d16f9478064213f3e6fbe9cd3a96dd730caa413464fadaf634337e810d5e6be7da15d7c142d309cb76fd0f6f5cf111e112d3030ad003308201cc30820153a00302010202090093380e1447d2f9ae300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138303531333139333334375a170d3233303531323139333334375a301e310b3009060355040613025553310f300d060355040a0c065350494646453076301006072a8648ce3d020106052b81040022036200045a307e9d2192c48622ce76fce31bb95860d98fcd272fb5b5737cdfe3c5a1cb499aed8ee60812b37d092b80382e2388f467ed3fb431ffafc82d3ad2cbac8a6e330587a1ee2f6d5045b5ed6f8fa5ede96784f255f0702bcbb3f99c9af3ea54af63a35d305b301d0603551d0e0416041487a5f357a2f035acc0f864c454e76ed3ba39c8e8300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630190603551d1104123010860e7370696666653a2f2f6c6f63616c300a06082a8648ce3d0403040367003064023013831ed77a8c0bd8ba164c74876eb2d3d41921bb91a80f69b8b83d01e780032a39b41cd197560bd0a344a74d9529260902305d789bea8c9f705b9e4e1a3d494300c50fb91678407aa0c9703db23fe61118ddacc98b5e88d2e375252613496192a9671a85010a5b3059301306072a8648ce3d020106082a8648ce3d030107034200041db49815c4dc0a343e25ba73a2f6add69a034f968f9319c34eb6ef89c2674c92a310ebcef9d393fb478c7f00ce4a1dd0926b54cf6bbae5544968cd933b1372f61220486558424e674565324b6d744b563143384738674b5450766c59536c4156675318988bebe005');
CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"data_type" varchar(255),"serial_number" varchar(255),"expires_at" datetime );
CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"type" varchar(255),"value" varchar(255) );
CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255),"spiffe_id" varchar(255),"parent_id" varchar(255),"ttl" integer, "admin" bool, "downstream" bool, "expiry" bigint);
INSERT INTO registered_entries VALUES(1,'2018-12-19 14:26:58.227869-07:00','2018-12-19 14:26:58.227869-07:00','f0373f87-a0f3-4c94-aa6a-a2f948bfc15a','spiffe://example.org/admin','spiffe://example.org/spire/agent/x509pop/e81aef2e9178db3db836a1a85d362ca5b2241631',3600, 0, 0, 0);
CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"token" varchar(255),"expiry" bigint );
CREATE TABLE IF NOT EXISTS "selectors" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"type" varchar(255),"value" varchar(255) );
INSERT INTO selectors VALUES(1,'2018-12-19 14:26:58.228067-07:00','2018-12-19 14:26:58.228067-07:00',1,'unix','uid:501');
CREATE TABLE IF NOT EXISTS "migrations" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"version" integer );
INSERT INTO migrations VALUES(1,'2018-12-19 14:26:32.297244-07:00','2018-12-19 14:26:32.297244-07:00',8);
CREATE TABLE IF NOT EXISTS "dns_names" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"value" varchar(255) );
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('migrations',1);
INSERT INTO sqlite_sequence VALUES('bundles',1);
INSERT INTO sqlite_sequence VALUES('registered_entries',1);
INSERT INTO sqlite_sequence VALUES('selectors',1);
CREATE UNIQUE INDEX uix_bundles_trust_domain ON "bundles"(trust_domain) ;
CREATE UNIQUE INDEX uix_attested_node_entries_spiffe_id ON "attested_node_entries"(spiffe_id) ;
CREATE UNIQUE INDEX idx_node_resolver_map ON "node_resolver_map_entries"(spiffe_id, "type", "value") ;
CREATE UNIQUE INDEX uix_registered_entries_entry_id ON "registered_entries"(entry_id) ;
CREATE UNIQUE INDEX uix_join_tokens_token ON "join_tokens"("token") ;
CREATE UNIQUE INDEX idx_selector_entry ON "selectors"(registered_entry_id, "type", "value") ;
CREATE UNIQUE INDEX idx_dns_entry ON "dns_names"(registered_entry_id, "value") ;
COMMIT;
`,
		// v9 database entry, in which indices were added to registration_entries spiffe ID and parent ID fields,
		// and selectors type-value unique index was added
		`
		PRAGMA foreign_keys=OFF;
		BEGIN TRANSACTION;
		CREATE TABLE IF NOT EXISTS "federated_registration_entries" ("bundle_id" integer,"registered_entry_id" integer, PRIMARY KEY ("bundle_id","registered_entry_id"));
		CREATE TABLE IF NOT EXISTS "bundles" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"data" blob );
		INSERT INTO bundles VALUES(1,'2018-12-19 14:26:32.340488-07:00','2018-12-19 14:26:32.340488-07:00','spiffe://example.org',X'0a147370696666653a2f2f6578616d706c652e6f726712f6030af303308201ef30820174a003020102020101300a06082a8648ce3d040303301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138313231393231323632325a170d3138313231393232323633325a301e310b3009060355040613025553310f300d060355040a13065350494646453076301006072a8648ce3d020106052b8104002203620004c941f4fdc386a57aa74807d64a05fdedac4d3c9cd0841beac744db4163ae6ba46e883551c683cf11781c8958ebb11ae9a4bbeb3bbf751aaa9e645e65ab6ee3c5b681621d538929956f37e182c8f955614bef67e7921b3371571b87a0065e0f8da38185308182300e0603551d0f0101ff040403020186300f0603551d130101ff040530030101ff301d0603551d0e04160414bb9e6ee33abb3b2d2587b5c67f66f74851487739301f0603551d2304183016801487a5f357a2f035acc0f864c454e76ed3ba39c8e8301f0603551d110418301686147370696666653a2f2f6578616d706c652e6f7267300a06082a8648ce3d0403030369003066023100813cc8650728e10cdfd5230d484dd4353ec7513dc2543cb51c1115dfb62d5d1ca92dd586137d273b4ad6a78a53dedc6c023100d16f9478064213f3e6fbe9cd3a96dd730caa413464fadaf634337e810d5e6be7da15d7c142d309cb76fd0f6f5cf111e112d3030ad003308201cc30820153a00302010202090093380e1447d2f9ae300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138303531333139333334375a170d3233303531323139333334375a301e310b3009060355040613025553310f300d060355040a0c065350494646453076301006072a8648ce3d020106052b81040022036200045a307e9d2192c48622ce76fce31bb95860d98fcd272fb5b5737cdfe3c5a1cb499aed8ee60812b37d092b80382e2388f467ed3fb431ffafc82d3ad2cbac8a6e330587a1ee2f6d5045b5ed6f8fa5ede96784f255f0702bcbb3f99c9af3ea54af63a35d305b301d0603551d0e0416041487a5f357a2f035acc0f864c454e76ed3ba39c8e8300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630190603551d1104123010860e7370696666653a2f2f6c6f63616c300a06082a8648ce3d0403040367003064023013831ed77a8c0bd8ba164c74876eb2d3d41921bb91a80f69b8b83d01e780032a39b41cd197560bd0a344a74d9529260902305d789bea8c9f705b9e4e1a3d494300c50fb91678407aa0c9703db23fe61118ddacc98b5e88d2e375252613496192a9671a85010a5b3059301306072a8648ce3d020106082a8648ce3d030107034200041db49815c4dc0a343e25ba73a2f6add69a034f968f9319c34eb6ef89c2674c92a310ebcef9d393fb478c7f00ce4a1dd0926b54cf6bbae5544968cd933b1372f61220486558424e674565324b6d744b563143384738674b5450766c59536c4156675318988bebe005');
		CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"data_type" varchar(255),"serial_number" varchar(255),"expires_at" datetime );
		CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"type" varchar(255),"value" varchar(255) );
		CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255),"spiffe_id" varchar(255),"parent_id" varchar(255),"ttl" integer, "admin" bool, "downstream" bool, "expiry" bigint);
		INSERT INTO registered_entries VALUES(1,'2018-12-19 14:26:58.227869-07:00','2018-12-19 14:26:58.227869-07:00','f0373f87-a0f3-4c94-aa6a-a2f948bfc15a','spiffe://example.org/admin','spiffe://example.org/spire/agent/x509pop/e81aef2e9178db3db836a1a85d362ca5b2241631',3600, 0, 0, 0);
		CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"token" varchar(255),"expiry" bigint );
		CREATE TABLE IF NOT EXISTS "selectors" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"type" varchar(255),"value" varchar(255) );
		INSERT INTO selectors VALUES(1,'2018-12-19 14:26:58.228067-07:00','2018-12-19 14:26:58.228067-07:00',1,'unix','uid:501');
		CREATE TABLE IF NOT EXISTS "migrations" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"version" integer );
		INSERT INTO migrations VALUES(1,'2018-12-19 14:26:32.297244-07:00','2018-12-19 14:26:32.297244-07:00',9);
		CREATE TABLE IF NOT EXISTS "dns_names" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"value" varchar(255) );
		DELETE FROM sqlite_sequence;
		INSERT INTO sqlite_sequence VALUES('migrations',1);
		INSERT INTO sqlite_sequence VALUES('bundles',1);
		INSERT INTO sqlite_sequence VALUES('registered_entries',1);
		INSERT INTO sqlite_sequence VALUES('selectors',1);
		CREATE UNIQUE INDEX uix_bundles_trust_domain ON "bundles"(trust_domain) ;
		CREATE UNIQUE INDEX uix_attested_node_entries_spiffe_id ON "attested_node_entries"(spiffe_id) ;
		CREATE UNIQUE INDEX idx_node_resolver_map ON "node_resolver_map_entries"(spiffe_id, "type", "value") ;
		CREATE UNIQUE INDEX uix_registered_entries_entry_id ON "registered_entries"(entry_id) ;
		CREATE UNIQUE INDEX uix_join_tokens_token ON "join_tokens"("token") ;
		CREATE UNIQUE INDEX idx_selector_entry ON "selectors"(registered_entry_id, "type", "value") ;
		CREATE UNIQUE INDEX idx_selectors_type_value ON "selectors"("type", "value") ;
		CREATE UNIQUE INDEX idx_dns_entry ON "dns_names"(registered_entry_id, "value") ;
		CREATE INDEX idx_registered_entries_spiffe_id ON "registered_entries"(spiffe_id) ;
		CREATE INDEX idx_registered_entries_parent_id ON "registered_entries"(parent_id) ;
		COMMIT;
		`,
		// v10 database entry, in which index was added to registration_entries expiry field
		`
		PRAGMA foreign_keys=OFF;
		BEGIN TRANSACTION;
		CREATE TABLE IF NOT EXISTS "federated_registration_entries" ("bundle_id" integer,"registered_entry_id" integer, PRIMARY KEY ("bundle_id","registered_entry_id"));
		CREATE TABLE IF NOT EXISTS "bundles" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"data" blob );
		INSERT INTO bundles VALUES(1,'2018-12-19 14:26:32.340488-07:00','2018-12-19 14:26:32.340488-07:00','spiffe://example.org',X'0a147370696666653a2f2f6578616d706c652e6f726712f6030af303308201ef30820174a003020102020101300a06082a8648ce3d040303301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138313231393231323632325a170d3138313231393232323633325a301e310b3009060355040613025553310f300d060355040a13065350494646453076301006072a8648ce3d020106052b8104002203620004c941f4fdc386a57aa74807d64a05fdedac4d3c9cd0841beac744db4163ae6ba46e883551c683cf11781c8958ebb11ae9a4bbeb3bbf751aaa9e645e65ab6ee3c5b681621d538929956f37e182c8f955614bef67e7921b3371571b87a0065e0f8da38185308182300e0603551d0f0101ff040403020186300f0603551d130101ff040530030101ff301d0603551d0e04160414bb9e6ee33abb3b2d2587b5c67f66f74851487739301f0603551d2304183016801487a5f357a2f035acc0f864c454e76ed3ba39c8e8301f0603551d110418301686147370696666653a2f2f6578616d706c652e6f7267300a06082a8648ce3d0403030369003066023100813cc8650728e10cdfd5230d484dd4353ec7513dc2543cb51c1115dfb62d5d1ca92dd586137d273b4ad6a78a53dedc6c023100d16f9478064213f3e6fbe9cd3a96dd730caa413464fadaf634337e810d5e6be7da15d7c142d309cb76fd0f6f5cf111e112d3030ad003308201cc30820153a00302010202090093380e1447d2f9ae300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138303531333139333334375a170d3233303531323139333334375a301e310b3009060355040613025553310f300d060355040a0c065350494646453076301006072a8648ce3d020106052b81040022036200045a307e9d2192c48622ce76fce31bb95860d98fcd272fb5b5737cdfe3c5a1cb499aed8ee60812b37d092b80382e2388f467ed3fb431ffafc82d3ad2cbac8a6e330587a1ee2f6d5045b5ed6f8fa5ede96784f255f0702bcbb3f99c9af3ea54af63a35d305b301d0603551d0e0416041487a5f357a2f035acc0f864c454e76ed3ba39c8e8300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630190603551d1104123010860e7370696666653a2f2f6c6f63616c300a06082a8648ce3d0403040367003064023013831ed77a8c0bd8ba164c74876eb2d3d41921bb91a80f69b8b83d01e780032a39b41cd197560bd0a344a74d9529260902305d789bea8c9f705b9e4e1a3d494300c50fb91678407aa0c9703db23fe61118ddacc98b5e88d2e375252613496192a9671a85010a5b3059301306072a8648ce3d020106082a8648ce3d030107034200041db49815c4dc0a343e25ba73a2f6add69a034f968f9319c34eb6ef89c2674c92a310ebcef9d393fb478c7f00ce4a1dd0926b54cf6bbae5544968cd933b1372f61220486558424e674565324b6d744b563143384738674b5450766c59536c4156675318988bebe005');
		CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"data_type" varchar(255),"serial_number" varchar(255),"expires_at" datetime );
		CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"type" varchar(255),"value" varchar(255) );
		CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255),"spiffe_id" varchar(255),"parent_id" varchar(255),"ttl" integer, "admin" bool, "downstream" bool, "expiry" bigint);
		INSERT INTO registered_entries VALUES(1,'2018-12-19 14:26:58.227869-07:00','2018-12-19 14:26:58.227869-07:00','f0373f87-a0f3-4c94-aa6a-a2f948bfc15a','spiffe://example.org/admin','spiffe://example.org/spire/agent/x509pop/e81aef2e9178db3db836a1a85d362ca5b2241631',3600, 0, 0, 0);
		CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"token" varchar(255),"expiry" bigint );
		CREATE TABLE IF NOT EXISTS "selectors" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"type" varchar(255),"value" varchar(255) );
		INSERT INTO selectors VALUES(1,'2018-12-19 14:26:58.228067-07:00','2018-12-19 14:26:58.228067-07:00',1,'unix','uid:501');
		CREATE TABLE IF NOT EXISTS "migrations" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"version" integer );
		INSERT INTO migrations VALUES(1,'2018-12-19 14:26:32.297244-07:00','2018-12-19 14:26:32.297244-07:00',10);
		CREATE TABLE IF NOT EXISTS "dns_names" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"value" varchar(255) );
		DELETE FROM sqlite_sequence;
		INSERT INTO sqlite_sequence VALUES('migrations',1);
		INSERT INTO sqlite_sequence VALUES('bundles',1);
		INSERT INTO sqlite_sequence VALUES('registered_entries',1);
		INSERT INTO sqlite_sequence VALUES('selectors',1);
		CREATE UNIQUE INDEX uix_bundles_trust_domain ON "bundles"(trust_domain) ;
		CREATE UNIQUE INDEX uix_attested_node_entries_spiffe_id ON "attested_node_entries"(spiffe_id) ;
		CREATE UNIQUE INDEX idx_node_resolver_map ON "node_resolver_map_entries"(spiffe_id, "type", "value") ;
		CREATE UNIQUE INDEX uix_registered_entries_entry_id ON "registered_entries"(entry_id) ;
		CREATE UNIQUE INDEX uix_join_tokens_token ON "join_tokens"("token") ;
		CREATE UNIQUE INDEX idx_selector_entry ON "selectors"(registered_entry_id, "type", "value") ;
		CREATE UNIQUE INDEX idx_selectors_type_value ON "selectors"("type", "value") ;
		CREATE UNIQUE INDEX idx_dns_entry ON "dns_names"(registered_entry_id, "value") ;
		CREATE INDEX idx_registered_entries_spiffe_id ON "registered_entries"(spiffe_id) ;
		CREATE INDEX idx_registered_entries_parent_id ON "registered_entries"(parent_id) ;
		CREATE INDEX idx_registered_entries_expiry ON "registered_entries"(expiry) ;
		COMMIT;
		`,
		// v11 database entry, in which index was added to federated_registration_entries registered_entry_id field
		`
		PRAGMA foreign_keys=OFF;
		BEGIN TRANSACTION;
		CREATE TABLE IF NOT EXISTS "federated_registration_entries" ("bundle_id" integer,"registered_entry_id" integer, PRIMARY KEY ("bundle_id","registered_entry_id"));
		CREATE TABLE IF NOT EXISTS "bundles" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"data" blob );
		INSERT INTO bundles VALUES(1,'2018-12-19 14:26:32.340488-07:00','2018-12-19 14:26:32.340488-07:00','spiffe://example.org',X'0a147370696666653a2f2f6578616d706c652e6f726712f6030af303308201ef30820174a003020102020101300a06082a8648ce3d040303301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138313231393231323632325a170d3138313231393232323633325a301e310b3009060355040613025553310f300d060355040a13065350494646453076301006072a8648ce3d020106052b8104002203620004c941f4fdc386a57aa74807d64a05fdedac4d3c9cd0841beac744db4163ae6ba46e883551c683cf11781c8958ebb11ae9a4bbeb3bbf751aaa9e645e65ab6ee3c5b681621d538929956f37e182c8f955614bef67e7921b3371571b87a0065e0f8da38185308182300e0603551d0f0101ff040403020186300f0603551d130101ff040530030101ff301d0603551d0e04160414bb9e6ee33abb3b2d2587b5c67f66f74851487739301f0603551d2304183016801487a5f357a2f035acc0f864c454e76ed3ba39c8e8301f0603551d110418301686147370696666653a2f2f6578616d706c652e6f7267300a06082a8648ce3d0403030369003066023100813cc8650728e10cdfd5230d484dd4353ec7513dc2543cb51c1115dfb62d5d1ca92dd586137d273b4ad6a78a53dedc6c023100d16f9478064213f3e6fbe9cd3a96dd730caa413464fadaf634337e810d5e6be7da15d7c142d309cb76fd0f6f5cf111e112d3030ad003308201cc30820153a00302010202090093380e1447d2f9ae300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138303531333139333334375a170d3233303531323139333334375a301e310b3009060355040613025553310f300d060355040a0c065350494646453076301006072a8648ce3d020106052b81040022036200045a307e9d2192c48622ce76fce31bb95860d98fcd272fb5b5737cdfe3c5a1cb499aed8ee60812b37d092b80382e2388f467ed3fb431ffafc82d3ad2cbac8a6e330587a1ee2f6d5045b5ed6f8fa5ede96784f255f0702bcbb3f99c9af3ea54af63a35d305b301d0603551d0e0416041487a5f357a2f035acc0f864c454e76ed3ba39c8e8300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630190603551d1104123010860e7370696666653a2f2f6c6f63616c300a06082a8648ce3d0403040367003064023013831ed77a8c0bd8ba164c74876eb2d3d41921bb91a80f69b8b83d01e780032a39b41cd197560bd0a344a74d9529260902305d789bea8c9f705b9e4e1a3d494300c50fb91678407aa0c9703db23fe61118ddacc98b5e88d2e375252613496192a9671a85010a5b3059301306072a8648ce3d020106082a8648ce3d030107034200041db49815c4dc0a343e25ba73a2f6add69a034f968f9319c34eb6ef89c2674c92a310ebcef9d393fb478c7f00ce4a1dd0926b54cf6bbae5544968cd933b1372f61220486558424e674565324b6d744b563143384738674b5450766c59536c4156675318988bebe005');
		CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"data_type" varchar(255),"serial_number" varchar(255),"expires_at" datetime );
		CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"type" varchar(255),"value" varchar(255) );
		CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255),"spiffe_id" varchar(255),"parent_id" varchar(255),"ttl" integer, "admin" bool, "downstream" bool, "expiry" bigint);
		INSERT INTO registered_entries VALUES(1,'2018-12-19 14:26:58.227869-07:00','2018-12-19 14:26:58.227869-07:00','f0373f87-a0f3-4c94-aa6a-a2f948bfc15a','spiffe://example.org/admin','spiffe://example.org/spire/agent/x509pop/e81aef2e9178db3db836a1a85d362ca5b2241631',3600, 0, 0, 0);
		CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"token" varchar(255),"expiry" bigint );
		CREATE TABLE IF NOT EXISTS "selectors" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"type" varchar(255),"value" varchar(255) );
		INSERT INTO selectors VALUES(1,'2018-12-19 14:26:58.228067-07:00','2018-12-19 14:26:58.228067-07:00',1,'unix','uid:501');
		CREATE TABLE IF NOT EXISTS "migrations" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"version" integer );
		INSERT INTO migrations VALUES(1,'2018-12-19 14:26:32.297244-07:00','2018-12-19 14:26:32.297244-07:00',11);
		CREATE TABLE IF NOT EXISTS "dns_names" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"value" varchar(255) );
		DELETE FROM sqlite_sequence;
		INSERT INTO sqlite_sequence VALUES('migrations',1);
		INSERT INTO sqlite_sequence VALUES('bundles',1);
		INSERT INTO sqlite_sequence VALUES('registered_entries',1);
		INSERT INTO sqlite_sequence VALUES('selectors',1);
		CREATE UNIQUE INDEX uix_bundles_trust_domain ON "bundles"(trust_domain) ;
		CREATE UNIQUE INDEX uix_attested_node_entries_spiffe_id ON "attested_node_entries"(spiffe_id) ;
		CREATE UNIQUE INDEX idx_node_resolver_map ON "node_resolver_map_entries"(spiffe_id, "type", "value") ;
		CREATE UNIQUE INDEX uix_registered_entries_entry_id ON "registered_entries"(entry_id) ;
		CREATE UNIQUE INDEX uix_join_tokens_token ON "join_tokens"("token") ;
		CREATE UNIQUE INDEX idx_selector_entry ON "selectors"(registered_entry_id, "type", "value") ;
		CREATE UNIQUE INDEX idx_selectors_type_value ON "selectors"("type", "value") ;
		CREATE UNIQUE INDEX idx_dns_entry ON "dns_names"(registered_entry_id, "value") ;
		CREATE INDEX idx_registered_entries_spiffe_id ON "registered_entries"(spiffe_id) ;
		CREATE INDEX idx_registered_entries_parent_id ON "registered_entries"(parent_id) ;
		CREATE INDEX idx_registered_entries_expiry ON "registered_entries"(expiry) ;
		CREATE INDEX idx_federated_registration_entries_registered_entry_id ON "federated_registration_entries"(registered_entry_id) ;
		COMMIT;
		`,
		// below this point is SPIRE Code version 0.9.X
		// v12 database entry, in which code_version string was added to migrations table
		`
		PRAGMA foreign_keys=OFF;
		BEGIN TRANSACTION;
		CREATE TABLE IF NOT EXISTS "federated_registration_entries" ("bundle_id" integer,"registered_entry_id" integer, PRIMARY KEY ("bundle_id","registered_entry_id"));
		CREATE TABLE IF NOT EXISTS "bundles" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"data" blob );
		INSERT INTO bundles VALUES(1,'2018-12-19 14:26:32.340488-07:00','2018-12-19 14:26:32.340488-07:00','spiffe://example.org',X'0a147370696666653a2f2f6578616d706c652e6f726712f6030af303308201ef30820174a003020102020101300a06082a8648ce3d040303301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138313231393231323632325a170d3138313231393232323633325a301e310b3009060355040613025553310f300d060355040a13065350494646453076301006072a8648ce3d020106052b8104002203620004c941f4fdc386a57aa74807d64a05fdedac4d3c9cd0841beac744db4163ae6ba46e883551c683cf11781c8958ebb11ae9a4bbeb3bbf751aaa9e645e65ab6ee3c5b681621d538929956f37e182c8f955614bef67e7921b3371571b87a0065e0f8da38185308182300e0603551d0f0101ff040403020186300f0603551d130101ff040530030101ff301d0603551d0e04160414bb9e6ee33abb3b2d2587b5c67f66f74851487739301f0603551d2304183016801487a5f357a2f035acc0f864c454e76ed3ba39c8e8301f0603551d110418301686147370696666653a2f2f6578616d706c652e6f7267300a06082a8648ce3d0403030369003066023100813cc8650728e10cdfd5230d484dd4353ec7513dc2543cb51c1115dfb62d5d1ca92dd586137d273b4ad6a78a53dedc6c023100d16f9478064213f3e6fbe9cd3a96dd730caa413464fadaf634337e810d5e6be7da15d7c142d309cb76fd0f6f5cf111e112d3030ad003308201cc30820153a00302010202090093380e1447d2f9ae300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138303531333139333334375a170d3233303531323139333334375a301e310b3009060355040613025553310f300d060355040a0c065350494646453076301006072a8648ce3d020106052b81040022036200045a307e9d2192c48622ce76fce31bb95860d98fcd272fb5b5737cdfe3c5a1cb499aed8ee60812b37d092b80382e2388f467ed3fb431ffafc82d3ad2cbac8a6e330587a1ee2f6d5045b5ed6f8fa5ede96784f255f0702bcbb3f99c9af3ea54af63a35d305b301d0603551d0e0416041487a5f357a2f035acc0f864c454e76ed3ba39c8e8300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630190603551d1104123010860e7370696666653a2f2f6c6f63616c300a06082a8648ce3d0403040367003064023013831ed77a8c0bd8ba164c74876eb2d3d41921bb91a80f69b8b83d01e780032a39b41cd197560bd0a344a74d9529260902305d789bea8c9f705b9e4e1a3d494300c50fb91678407aa0c9703db23fe61118ddacc98b5e88d2e375252613496192a9671a85010a5b3059301306072a8648ce3d020106082a8648ce3d030107034200041db49815c4dc0a343e25ba73a2f6add69a034f968f9319c34eb6ef89c2674c92a310ebcef9d393fb478c7f00ce4a1dd0926b54cf6bbae5544968cd933b1372f61220486558424e674565324b6d744b563143384738674b5450766c59536c4156675318988bebe005');
		CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"data_type" varchar(255),"serial_number" varchar(255),"expires_at" datetime );
		CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"type" varchar(255),"value" varchar(255) );
		CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255),"spiffe_id" varchar(255),"parent_id" varchar(255),"ttl" integer, "admin" bool, "downstream" bool, "expiry" bigint);
		INSERT INTO registered_entries VALUES(1,'2018-12-19 14:26:58.227869-07:00','2018-12-19 14:26:58.227869-07:00','f0373f87-a0f3-4c94-aa6a-a2f948bfc15a','spiffe://example.org/admin','spiffe://example.org/spire/agent/x509pop/e81aef2e9178db3db836a1a85d362ca5b2241631',3600, 0, 0, 0);
		CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"token" varchar(255),"expiry" bigint );
		CREATE TABLE IF NOT EXISTS "selectors" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"type" varchar(255),"value" varchar(255) );
		INSERT INTO selectors VALUES(1,'2018-12-19 14:26:58.228067-07:00','2018-12-19 14:26:58.228067-07:00',1,'unix','uid:501');
		CREATE TABLE IF NOT EXISTS "migrations" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"version" integer,"code_version" varchar(255) );
		INSERT INTO migrations VALUES(1,'2018-12-19 14:26:32.297244-07:00','2018-12-19 14:26:32.297244-07:00',12,'0.9.0');
		CREATE TABLE IF NOT EXISTS "dns_names" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"value" varchar(255) );
		DELETE FROM sqlite_sequence;
		INSERT INTO sqlite_sequence VALUES('migrations',1);
		INSERT INTO sqlite_sequence VALUES('bundles',1);
		INSERT INTO sqlite_sequence VALUES('registered_entries',1);
		INSERT INTO sqlite_sequence VALUES('selectors',1);
		CREATE UNIQUE INDEX uix_bundles_trust_domain ON "bundles"(trust_domain) ;
		CREATE UNIQUE INDEX uix_attested_node_entries_spiffe_id ON "attested_node_entries"(spiffe_id) ;
		CREATE UNIQUE INDEX idx_node_resolver_map ON "node_resolver_map_entries"(spiffe_id, "type", "value") ;
		CREATE UNIQUE INDEX uix_registered_entries_entry_id ON "registered_entries"(entry_id) ;
		CREATE UNIQUE INDEX uix_join_tokens_token ON "join_tokens"("token") ;
		CREATE UNIQUE INDEX idx_selector_entry ON "selectors"(registered_entry_id, "type", "value") ;
		CREATE UNIQUE INDEX idx_selectors_type_value ON "selectors"("type", "value") ;
		CREATE UNIQUE INDEX idx_dns_entry ON "dns_names"(registered_entry_id, "value") ;
		CREATE INDEX idx_registered_entries_spiffe_id ON "registered_entries"(spiffe_id) ;
		CREATE INDEX idx_registered_entries_parent_id ON "registered_entries"(parent_id) ;
		CREATE INDEX idx_registered_entries_expiry ON "registered_entries"(expiry) ;
		CREATE INDEX idx_federated_registration_entries_registered_entry_id ON "federated_registration_entries"(registered_entry_id) ;
		INSERT INTO attested_node_entries VALUES(1,'2018-12-19 14:26:58.227869-07:00','2018-12-19 14:26:58.227869-07:00','spiffe://example.org/host','test','111','2018-12-19 15:26:58-07:00');
		COMMIT;
		`,
		// v13 database entry, in which the table 'attested_node_entries' gained two columns: 'new_serial_number' and 'new_expires_at'
		`
		PRAGMA foreign_keys=OFF;
		BEGIN TRANSACTION;
		CREATE TABLE IF NOT EXISTS "federated_registration_entries" ("bundle_id" integer,"registered_entry_id" integer, PRIMARY KEY ("bundle_id","registered_entry_id"));
		CREATE TABLE IF NOT EXISTS "bundles" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"data" blob );
		INSERT INTO bundles VALUES(1,'2018-12-19 14:26:32.340488-07:00','2018-12-19 14:26:32.340488-07:00','spiffe://example.org',X'0a147370696666653a2f2f6578616d706c652e6f726712f6030af303308201ef30820174a003020102020101300a06082a8648ce3d040303301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138313231393231323632325a170d3138313231393232323633325a301e310b3009060355040613025553310f300d060355040a13065350494646453076301006072a8648ce3d020106052b8104002203620004c941f4fdc386a57aa74807d64a05fdedac4d3c9cd0841beac744db4163ae6ba46e883551c683cf11781c8958ebb11ae9a4bbeb3bbf751aaa9e645e65ab6ee3c5b681621d538929956f37e182c8f955614bef67e7921b3371571b87a0065e0f8da38185308182300e0603551d0f0101ff040403020186300f0603551d130101ff040530030101ff301d0603551d0e04160414bb9e6ee33abb3b2d2587b5c67f66f74851487739301f0603551d2304183016801487a5f357a2f035acc0f864c454e76ed3ba39c8e8301f0603551d110418301686147370696666653a2f2f6578616d706c652e6f7267300a06082a8648ce3d0403030369003066023100813cc8650728e10cdfd5230d484dd4353ec7513dc2543cb51c1115dfb62d5d1ca92dd586137d273b4ad6a78a53dedc6c023100d16f9478064213f3e6fbe9cd3a96dd730caa413464fadaf634337e810d5e6be7da15d7c142d309cb76fd0f6f5cf111e112d3030ad003308201cc30820153a00302010202090093380e1447d2f9ae300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3138303531333139333334375a170d3233303531323139333334375a301e310b3009060355040613025553310f300d060355040a0c065350494646453076301006072a8648ce3d020106052b81040022036200045a307e9d2192c48622ce76fce31bb95860d98fcd272fb5b5737cdfe3c5a1cb499aed8ee60812b37d092b80382e2388f467ed3fb431ffafc82d3ad2cbac8a6e330587a1ee2f6d5045b5ed6f8fa5ede96784f255f0702bcbb3f99c9af3ea54af63a35d305b301d0603551d0e0416041487a5f357a2f035acc0f864c454e76ed3ba39c8e8300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630190603551d1104123010860e7370696666653a2f2f6c6f63616c300a06082a8648ce3d0403040367003064023013831ed77a8c0bd8ba164c74876eb2d3d41921bb91a80f69b8b83d01e780032a39b41cd197560bd0a344a74d9529260902305d789bea8c9f705b9e4e1a3d494300c50fb91678407aa0c9703db23fe61118ddacc98b5e88d2e375252613496192a9671a85010a5b3059301306072a8648ce3d020106082a8648ce3d030107034200041db49815c4dc0a343e25ba73a2f6add69a034f968f9319c34eb6ef89c2674c92a310ebcef9d393fb478c7f00ce4a1dd0926b54cf6bbae5544968cd933b1372f61220486558424e674565324b6d744b563143384738674b5450766c59536c4156675318988bebe005');
		CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"data_type" varchar(255),"serial_number" varchar(255),"expires_at" datetime,"new_serial_number" varchar(255),"new_expires_at" datetime );
		CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"type" varchar(255),"value" varchar(255) );
		CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255),"spiffe_id" varchar(255),"parent_id" varchar(255),"ttl" integer, "admin" bool, "downstream" bool, "expiry" bigint);
		INSERT INTO registered_entries VALUES(1,'2018-12-19 14:26:58.227869-07:00','2018-12-19 14:26:58.227869-07:00','f0373f87-a0f3-4c94-aa6a-a2f948bfc15a','spiffe://example.org/admin','spiffe://example.org/spire/agent/x509pop/e81aef2e9178db3db836a1a85d362ca5b2241631',3600, 0, 0, 0);
		CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"token" varchar(255),"expiry" bigint );
		CREATE TABLE IF NOT EXISTS "selectors" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"type" varchar(255),"value" varchar(255) );
		INSERT INTO selectors VALUES(1,'2018-12-19 14:26:58.228067-07:00','2018-12-19 14:26:58.228067-07:00',1,'unix','uid:501');
		CREATE TABLE IF NOT EXISTS "migrations" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"version" integer,"code_version" varchar(255) );
		INSERT INTO migrations VALUES(1,'2018-12-19 14:26:32.297244-07:00','2018-12-19 14:26:32.297244-07:00',12,'0.9.0');
		CREATE TABLE IF NOT EXISTS "dns_names" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"value" varchar(255) );
		DELETE FROM sqlite_sequence;
		INSERT INTO sqlite_sequence VALUES('migrations',1);
		INSERT INTO sqlite_sequence VALUES('bundles',1);
		INSERT INTO sqlite_sequence VALUES('registered_entries',1);
		INSERT INTO sqlite_sequence VALUES('selectors',1);
		CREATE UNIQUE INDEX uix_bundles_trust_domain ON "bundles"(trust_domain) ;
		CREATE UNIQUE INDEX uix_attested_node_entries_spiffe_id ON "attested_node_entries"(spiffe_id) ;
		CREATE UNIQUE INDEX idx_node_resolver_map ON "node_resolver_map_entries"(spiffe_id, "type", "value") ;
		CREATE UNIQUE INDEX uix_registered_entries_entry_id ON "registered_entries"(entry_id) ;
		CREATE UNIQUE INDEX uix_join_tokens_token ON "join_tokens"("token") ;
		CREATE UNIQUE INDEX idx_selector_entry ON "selectors"(registered_entry_id, "type", "value") ;
		CREATE UNIQUE INDEX idx_selectors_type_value ON "selectors"("type", "value") ;
		CREATE UNIQUE INDEX idx_dns_entry ON "dns_names"(registered_entry_id, "value") ;
		CREATE INDEX idx_registered_entries_spiffe_id ON "registered_entries"(spiffe_id) ;
		CREATE INDEX idx_registered_entries_parent_id ON "registered_entries"(parent_id) ;
		CREATE INDEX idx_registered_entries_expiry ON "registered_entries"(expiry) ;
		CREATE INDEX idx_federated_registration_entries_registered_entry_id ON "federated_registration_entries"(registered_entry_id) ;
		INSERT INTO attested_node_entries VALUES(1,'2018-12-19 14:26:58.227869-07:00','2018-12-19 14:26:58.227869-07:00','spiffe://example.org/host','test','111','2018-12-19 15:26:58-07:00','112','2020-03-04 14:48:00-07:00');
		COMMIT;
		`,
		// future v14 database entry, in which the table 'registered_entries' gained one new column: 'type'
	}
)

func migrationDump(n int) string {
	if len(migrationDumps) > n {
		return migrationDumps[n]
	}
	return ""
}

func dumpDB(path string, statements string) error {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return sqlError.Wrap(err)
	}
	if _, err := db.Exec(statements); err != nil {
		db.Close()
		return sqlError.Wrap(err)
	}

	if err := db.Close(); err != nil {
		return sqlError.Wrap(err)
	}

	return nil
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
		dbCodeVersion    semver.Version
		expectCompatible bool
	}{
		{
			desc:             "backwards compatible 1 minor version",
			dbCodeVersion:    semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor - 1)},
			expectCompatible: true,
		},
		{
			desc:             "forwards compatible 1 minor version",
			dbCodeVersion:    semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor + 1)},
			expectCompatible: true,
		},
		{
			desc:             "compatible with self",
			dbCodeVersion:    codeVersion,
			expectCompatible: true,
		},
		{
			desc:             "not backwards compatible 2 minor versions",
			dbCodeVersion:    semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor - 2)},
			expectCompatible: false,
		},
		{
			desc:             "not forwards compatible 2 minor versions",
			dbCodeVersion:    semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor + 2)},
			expectCompatible: false,
		},
		{
			desc:             "not compatible with different major version",
			dbCodeVersion:    semver.Version{Major: (codeVersion.Major + 1), Minor: codeVersion.Minor},
			expectCompatible: false,
		},
	}

	for _, tt := range tests {
		tt := tt // alias loop variable as it is used in the closure
		t.Run(tt.desc, func(t *testing.T) {
			compatible := isCompatibleCodeVersion(tt.dbCodeVersion)

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
			err := isDisabledMigrationAllowed(tt.dbCodeVersion)

			if tt.expectErr != "" {
				require.Error(t, err)
				assert.Equal(t, tt.expectErr, err.Error())
				return
			}

			assert.NoError(t, err)
		})
	}
}
