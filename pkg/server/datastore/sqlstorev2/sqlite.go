//go:build cgo

package sqlstorev2

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type sqliteDB struct {
	log logrus.FieldLogger
}

func (s sqliteDB) connect(ctx context.Context, cfg *sqlcommon.Configuration, isReadOnly bool) (db *gorm.DB, version string, supportsCTE bool, err error) {
	if isReadOnly {
		s.log.Warn("Read-only connection is not applicable for sqlite3. Falling back to primary connection")
	}

	embellished, err := sqlcommon.EmbellishSQLite3ConnString(cfg.ConnectionString)
	if err != nil {
		return nil, "", false, err
	}

	db, err = gorm.Open(sqlite.Open(embellished), gormConfig(cfg, s.log))
	if err != nil {
		return nil, "", false, newWrappedSQLError(err)
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
