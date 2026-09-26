package sqlstorev2

import (
	"context"
	"database/sql"
	"errors"

	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"github.com/spiffe/spire/pkg/server/datastore/sqldriver/awsrds"
	"github.com/spiffe/spire/pkg/server/datastore/sqldriver/azurerds"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type postgresDB struct{}

func (p postgresDB) connect(ctx context.Context, cfg *sqlcommon.Configuration, isReadOnly bool) (db *gorm.DB, version string, supportsCTE bool, err error) {
	if cfg.DBTypeConfig == nil {
		return nil, "", false, errors.New("missing datastore configuration")
	}

	switch {
	case cfg.DBTypeConfig.AWSPostgres != nil:
		dsn, err := sqlcommon.BuildAWSPostgresDSN(cfg, isReadOnly)
		if err != nil {
			return nil, "", false, err
		}
		db, err = openSQLDriver(awsrds.PostgresDriverName, dsn, newPostgresDialector)
		if err != nil {
			return nil, "", false, err
		}
	case cfg.DBTypeConfig.AzurePostgres != nil:
		dsn, err := sqlcommon.BuildAzurePostgresDSN(cfg, isReadOnly)
		if err != nil {
			return nil, "", false, err
		}
		db, err = openSQLDriver(azurerds.PostgresDriverName, dsn, newPostgresDialector)
		if err != nil {
			return nil, "", false, err
		}
	default:
		connString := sqlcommon.GetConnectionString(cfg, isReadOnly)
		db, err = gorm.Open(postgres.Open(connString), gormConfig())
		if err != nil {
			return nil, "", false, err
		}
	}

	version, err = queryVersion(ctx, db, sqlcommon.PostgresVersionQuery)
	if err != nil {
		return nil, "", false, closeOnError(db, err)
	}

	// Supported versions of PostgreSQL all support CTE.
	return db, version, true, nil
}

func (p postgresDB) isConstraintViolation(err error) bool {
	return sqlcommon.IsPostgresConstraintViolation(err)
}

func newPostgresDialector(conn *sql.DB) gorm.Dialector {
	return postgres.New(postgres.Config{Conn: conn})
}
