package sqlstorev2

import (
	"context"
	"database/sql"
	"errors"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"github.com/spiffe/spire/pkg/server/datastore/sqldriver/awsrds"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type postgresDB struct {
	log logrus.FieldLogger
}

func (p postgresDB) connect(ctx context.Context, cfg *sqlcommon.Configuration, isReadOnly bool) (db *gorm.DB, version string, supportsCTE bool, err error) {
	if cfg.DBTypeConfig == nil {
		return nil, "", false, errors.New("missing datastore configuration")
	}

	switch {
	case cfg.DBTypeConfig.AWSPostgres != nil:
		dsn, err := sqlcommon.BuildAWSPostgresDSN(cfg)
		if err != nil {
			return nil, "", false, err
		}
		sqlDB, err := sql.Open(awsrds.PostgresDriverName, dsn)
		if err != nil {
			return nil, "", false, newWrappedSQLError(err)
		}
		db, err = gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), gormConfig(cfg, p.log))
		if err != nil {
			return nil, "", false, newWrappedSQLError(err)
		}
	default:
		connString := sqlcommon.GetConnectionString(cfg, isReadOnly)
		db, err = gorm.Open(postgres.Open(connString), gormConfig(cfg, p.log))
		if err != nil {
			return nil, "", false, newWrappedSQLError(err)
		}
	}

	version, err = queryVersion(ctx, db, sqlcommon.PostgresVersionQuery)
	if err != nil {
		return nil, "", false, err
	}

	// Supported versions of PostgreSQL all support CTE.
	return db, version, true, nil
}

func (p postgresDB) isConstraintViolation(err error) bool {
	return sqlcommon.IsPostgresConstraintViolation(err)
}
