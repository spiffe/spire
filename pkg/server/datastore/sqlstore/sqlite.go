//go:build cgo

package sqlstore

import (
	"errors"
	"net/url"
	"path/filepath"
	"runtime"

	"github.com/jinzhu/gorm"
	"github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"

	// gorm sqlite dialect init registration
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

type sqliteDB struct {
	log logrus.FieldLogger
}

func (s sqliteDB) connect(cfg *configuration, isReadOnly bool) (db *gorm.DB, version string, supportsCTE bool, err error) {
	if isReadOnly {
		s.log.Warn("Read-only connection is not applicable for sqlite3. Falling back to primary connection")
	}

	db, err = openSQLite3(cfg.ConnectionString)
	if err != nil {
		return nil, "", false, err
	}

	version, err = queryVersion(db, "SELECT sqlite_version()")
	if err != nil {
		return nil, "", false, err
	}

	// The embedded version of SQLite3 unconditionally supports CTE.
	return db, version, true, nil
}

func (s sqliteDB) isConstraintViolation(err error) bool {
	if err == nil {
		return false
	}
	var e sqlite3.Error
	ok := errors.As(err, &e)
	return ok && e.Code == sqlite3.ErrConstraint
}

func openSQLite3(connString string) (*gorm.DB, error) {
	embellished, err := embellishSQLite3ConnString(connString)
	if err != nil {
		return nil, err
	}
	db, err := gorm.Open("sqlite3", embellished)
	if err != nil {
		return nil, newWrappedSQLError(err)
	}
	return db, nil
}

// embellishSQLite3ConnString adds query values supported by
// github.com/mattn/go-sqlite3 to enable journal mode and foreign key support.
// These query values MUST be part of the connection string in order to be
// enabled for *each* connection opened by db/sql. If the connection string is
// not already a file: URI, it is converted first.
func embellishSQLite3ConnString(connectionString string) (string, error) {
	// On Windows, when parsing an absolute path like "c:\tmp\lite",
	// "c" is parsed as the URL scheme
	if runtime.GOOS == "windows" && filepath.IsAbs(connectionString) {
		connectionString = "/" + connectionString
	}

	u, err := url.Parse(connectionString)
	if err != nil {
		return "", newWrappedSQLError(err)
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
		return "", newSQLError("unsupported scheme %q", u.Scheme)
	}

	q := u.Query()
	q.Set("_foreign_keys", "ON")
	q.Set("_journal_mode", "WAL")
	u.RawQuery = q.Encode()
	return u.String(), nil
}
