package sqlstorev2

import (
	"context"
	"database/sql"
	"errors"

	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"gorm.io/gorm"
)

// dialect abstracts the per-database-engine connection and error
// classification logic. The returned *gorm.DB is a gorm v2 handle.
type dialect interface {
	connect(ctx context.Context, cfg *sqlcommon.Configuration, isReadOnly bool) (
		db *gorm.DB, version string, supportsCTE bool, err error)
	isConstraintViolation(err error) bool
}

// openSQLDriver opens dsn with a registered database/sql driver, such as the
// AWS or Azure token-authenticating wrappers, and hands the resulting pool to
// GORM through newDialector.
func openSQLDriver(driverName, dsn string, newDialector func(*sql.DB) gorm.Dialector) (*gorm.DB, error) {
	sqlDB, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}
	db, err := gorm.Open(newDialector(sqlDB), gormConfig())
	if err != nil {
		return nil, errors.Join(err, sqlDB.Close())
	}
	return db, nil
}
