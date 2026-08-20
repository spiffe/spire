//go:build cgo

package sqlstore

import (
	"context"

	"github.com/jinzhu/gorm"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"

	// gorm sqlite dialect init registration
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

type sqliteDB struct {
	log logrus.FieldLogger
}

func (s sqliteDB) connect(ctx context.Context, cfg *sqlcommon.Configuration, isReadOnly bool) (db *gorm.DB, version string, supportsCTE bool, err error) {
	if isReadOnly {
		s.log.Warn("Read-only connection is not applicable for sqlite3. Falling back to primary connection")
	}

	db, err = openSQLite3(cfg.ConnectionString)
	if err != nil {
		return nil, "", false, err
	}

	version, err = queryVersion(ctx, db, sqlcommon.SQLiteVersionQuery)
	if err != nil {
		return nil, "", false, err
	}

	// The embedded version of SQLite3 unconditionally supports CTE.
	return db, version, true, nil
}

func (s sqliteDB) isConstraintViolation(err error) bool {
	return sqlcommon.IsSQLiteConstraintViolation(err)
}

func openSQLite3(connString string) (*gorm.DB, error) {
	embellished, err := sqlcommon.EmbellishSQLite3ConnString(connString)
	if err != nil {
		return nil, err
	}
	db, err := gorm.Open("sqlite3", embellished)
	if err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}
	return db, nil
}
