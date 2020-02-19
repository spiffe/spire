package sql

import (
	"net/url"

	"github.com/jinzhu/gorm"

	// gorm sqlite dialect init registration
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	_ "github.com/spiffe/spire/pkg/server/plugin/datastore"
)

type sqliteDB struct{}

func (s sqliteDB) connect(cfg *configuration) (*gorm.DB, string, bool, error) {
	embellished, err := embellishSQLite3ConnString(cfg.ConnectionString)
	if err != nil {
		return nil, "", false, err
	}
	db, err := gorm.Open("sqlite3", embellished)
	if err != nil {
		return nil, "", false, sqlError.Wrap(err)
	}

	version, err := queryVersion(db, "SELECT sqlite_version()")
	if err != nil {
		return nil, "", false, err
	}

	return db, version, true, nil
}

// embellishSQLite3ConnString adds query values supported by
// github.com/mattn/go-sqlite3 to enable journal mode and foreign key support.
// These query values MUST be part of the connection string in order to be
// enabled for *each* connection opened by db/sql. If the connection string is
// not already a file: URI, it is converted first.
func embellishSQLite3ConnString(connectionString string) (string, error) {
	u, err := url.Parse(connectionString)
	if err != nil {
		return "", sqlError.Wrap(err)
	}

	switch {
	case u.Scheme == "":
		// connection string is a path. move the path section into the
		// opaque section so it renders property for sqlite3, for example:
		// data.db = file:data.db
		// ./data.db = file:./data.db
		// /data.db = file:/data.db
		u.Scheme = "file"
		u.Opaque, u.Path = u.Path, ""
	case u.Scheme != "file":
		// only no scheme (i.e. file path) or file scheme is supported
		return "", sqlError.New("unsupported scheme %q", u.Scheme)
	}

	q := u.Query()
	q.Set("_foreign_keys", "ON")
	q.Set("_journal_mode", "WAL")
	u.RawQuery = q.Encode()
	return u.String(), nil
}
