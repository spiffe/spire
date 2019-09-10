package sql

import (
	"bytes"
	"database/sql"
	"fmt"
	"path/filepath"
)

// Creates a database at a specified migration level
func createTestDB(targetlevel int, s *PluginSuite) string {
	dbName := fmt.Sprintf("v%d.sqlite3", targetlevel)
	dbPath := filepath.Join(s.dir, "migrationtest-"+dbName)

	database, _ := sql.Open("sqlite3", dbPath)
	dump := migrationDump(5)

	_, err := database.Exec(dump)
	s.Require().NoError(err)

	database.Close()

	return dbPath
}

func (s *PluginSuite) TestDryRunOutput() {
	dbPath := createTestDB(5, s)

	db, err := sqlite{}.connect(&configuration{
		DatabaseType:     "sqlite3",
		ConnectionString: fmt.Sprintf("file://%s", dbPath),
		MigrationDryRun:  true,
	})

	s.Require().NoError(err)

	db.LogMode(true)
	migratelogger := MigrationLogger{}

	testlogger := bytes.NewBufferString("")
	migratelogger.SetOutput(testlogger)
	db.SetLogger(&migratelogger)

	err = migrateToV6(db)
	s.Require().NoError(err)
	s.Require().Equal(testlogger.String(), "ALTER TABLE \"registered_entries\" ADD \"downstream\" bool;\n")

	testlogger = bytes.NewBufferString("")
	migratelogger.SetOutput(testlogger)
	err = migrateToV7(db)
	s.Require().NoError(err)
	s.Require().Equal(testlogger.String(), "ALTER TABLE \"registered_entries\" ADD \"expiry\" bigint;\n")

	testlogger = bytes.NewBufferString("")
	migratelogger.SetOutput(testlogger)
	err = migrateToV8(db)
	s.Require().NoError(err)
	s.Require().Equal(testlogger.String(), "CREATE TABLE \"dns_names\" (\"id\" integer primary key autoincrement,\"created_at\" datetime,\"updated_at\" datetime,\"registered_entry_id\" integer,\"value\" varchar(255) );\nCREATE UNIQUE INDEX idx_dns_entry ON \"dns_names\"(registered_entry_id, \"value\") ;\n")

	testlogger = bytes.NewBufferString("")
	migratelogger.SetOutput(testlogger)
	err = migrateToV9(db)
	s.Require().NoError(err)
	s.Require().Equal(testlogger.String(), "CREATE INDEX idx_registered_entries_spiffe_id ON \"registered_entries\"(spiffe_id) ;\nCREATE INDEX idx_registered_entries_parent_id ON \"registered_entries\"(parent_id) ;\nCREATE INDEX idx_selectors_type_value ON \"selectors\"(\"type\", \"value\") ;\n")

	testlogger = bytes.NewBufferString("")
	migratelogger.SetOutput(testlogger)
	err = migrateToV10(db)
	s.Require().NoError(err)
	s.Require().Equal(testlogger.String(), "CREATE INDEX idx_registered_entries_expiry ON \"registered_entries\"(\"expiry\") ;\n")
}
