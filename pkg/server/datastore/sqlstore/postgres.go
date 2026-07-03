package sqlstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jinzhu/gorm"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"github.com/spiffe/spire/pkg/server/datastore/sqldriver/awsrds"

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
		c, err := pgx.ParseConfig(connString)
		if err != nil {
			return nil, "", false, err
		}
		if c.Password != "" {
			return nil, "", false, errors.New("invalid postgres configuration: password should not be set when using IAM authentication")
		}

		awsrdsConfig := &awsrds.Config{
			Region:          cfg.DBTypeConfig.AWSPostgres.Region,
			AccessKeyID:     cfg.DBTypeConfig.AWSPostgres.AccessKeyID,
			SecretAccessKey: cfg.DBTypeConfig.AWSPostgres.SecretAccessKey,
			Endpoint:        fmt.Sprintf("%s:%d", c.Host, c.Port),
			DbUser:          c.User,
			DriverName:      awsrds.PostgresDriverName,
			ConnString:      connString,
		}
		dsn, err := awsrdsConfig.FormatDSN()
		if err != nil {
			return nil, "", false, err
		}
		db, errOpen = gorm.Open(awsrds.PostgresDriverName, dsn)
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
