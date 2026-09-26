package sqlstore

import (
	"context"
	"errors"

	"github.com/jinzhu/gorm"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"github.com/spiffe/spire/pkg/server/datastore/sqldriver/awsrds"
	"github.com/spiffe/spire/pkg/server/datastore/sqldriver/azurerds"

	// gorm postgres `cloudsql` dialect, for GCP Cloud SQL Proxy
	_ "github.com/GoogleCloudPlatform/cloudsql-proxy/proxy/dialers/postgres"
	// gorm postgres dialect init registration
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

type postgresDB struct{}

func (p postgresDB) connect(ctx context.Context, cfg *sqlcommon.Configuration, isReadOnly bool) (db *gorm.DB, version string, supportsCTE bool, err error) {
	if cfg.DBTypeConfig == nil {
		return nil, "", false, errors.New("missing datastore configuration")
	}

	connString := sqlcommon.GetConnectionString(cfg, isReadOnly)
	var errOpen error
	switch {
	case cfg.DBTypeConfig.AWSPostgres != nil:
		dsn, err := sqlcommon.BuildAWSPostgresDSN(cfg, isReadOnly)
		if err != nil {
			return nil, "", false, err
		}
		db, errOpen = gorm.Open(awsrds.PostgresDriverName, dsn)
	case cfg.DBTypeConfig.AzurePostgres != nil:
		dsn, err := sqlcommon.BuildAzurePostgresDSN(cfg, isReadOnly)
		if err != nil {
			return nil, "", false, err
		}
		db, errOpen = gorm.Open(azurerds.PostgresDriverName, dsn)
	default:
		db, errOpen = gorm.Open("postgres", connString)
	}

	if errOpen != nil {
		return nil, "", false, errOpen
	}

	version, err = queryVersion(ctx, db, sqlcommon.PostgresVersionQuery)
	if err != nil {
		return nil, "", false, err
	}

	// Supported versions of PostgreSQL all support CTE so unconditionally
	// return true.
	return db, version, true, nil
}

func (p postgresDB) isConstraintViolation(err error) bool {
	return sqlcommon.IsPostgresConstraintViolation(err)
}
