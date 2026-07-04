package sqlcommon

import (
	"net/url"
	"path/filepath"
	"runtime"
)

// EmbellishSQLite3ConnString adds query values supported by
// github.com/mattn/go-sqlite3 to enable journal mode and foreign key support.
// These query values MUST be part of the connection string in order to be
// enabled for *each* connection opened by db/sql. If the connection string is
// not already a file: URI, it is converted first.
func EmbellishSQLite3ConnString(connectionString string) (string, error) {
	// On Windows, when parsing an absolute path like "c:\tmp\lite",
	// "c" is parsed as the URL scheme
	if runtime.GOOS == "windows" && filepath.IsAbs(connectionString) {
		connectionString = "/" + connectionString
	}

	u, err := url.Parse(connectionString)
	if err != nil {
		return "", NewWrappedSQLError(err)
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
		return "", NewSQLError("unsupported scheme %q", u.Scheme)
	}

	q := u.Query()
	q.Set("_foreign_keys", "ON")
	q.Set("_journal_mode", "WAL")
	u.RawQuery = q.Encode()
	return u.String(), nil
}
