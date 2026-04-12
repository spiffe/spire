package sqlstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jinzhu/gorm"
	"github.com/lib/pq"
	"github.com/spiffe/spire/pkg/server/datastore/sqldriver/awsrds"

	// gorm postgres `cloudsql` dialect, for GCP Cloud SQL Proxy
	_ "github.com/GoogleCloudPlatform/cloudsql-proxy/proxy/dialers/postgres"
	// gorm postgres dialect init registration
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

type postgresDB struct{}

func (p postgresDB) connect(ctx context.Context, cfg *configuration, isReadOnly bool) (db *gorm.DB, version string, supportsCTE bool, err error) {
	if cfg.databaseTypeConfig == nil {
		return nil, "", false, errors.New("missing datastore configuration")
	}

	connString := getConnectionString(cfg, isReadOnly)
	var errOpen error
	switch {
	case cfg.databaseTypeConfig.AWSPostgres != nil:
		c, err := pgx.ParseConfig(connString)
		if err != nil {
			return nil, "", false, err
		}
		if c.Password != "" {
			return nil, "", false, errors.New("invalid postgres configuration: password should not be set when using IAM authentication")
		}

		awsrdsConfig := &awsrds.Config{
			Region:          cfg.databaseTypeConfig.AWSPostgres.Region,
			AccessKeyID:     cfg.databaseTypeConfig.AWSPostgres.AccessKeyID,
			SecretAccessKey: cfg.databaseTypeConfig.AWSPostgres.SecretAccessKey,
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

	version, err = queryVersion(ctx, db, "SHOW server_version")
	if err != nil {
		return nil, "", false, err
	}

	// Supported versions of PostgreSQL all support CTE so unconditionally
	// return true.
	return db, version, true, nil
}

func (p postgresDB) isConstraintViolation(err error) bool {
	var e *pq.Error
	ok := errors.As(err, &e)
	// "23xxx" is the constraint violation class for PostgreSQL
	return ok && e.Code.Class() == "23"
}
