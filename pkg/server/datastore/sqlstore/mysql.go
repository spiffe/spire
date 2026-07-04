package sqlstore

import (
	"context"
	"errors"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"github.com/spiffe/spire/pkg/server/datastore/sqldriver/awsrds"
	"github.com/spiffe/spire/pkg/server/datastore/sqldriver/azurerds"

	// gorm mysql `cloudsql` dialect, for GCP
	// Cloud SQL Proxy
	_ "github.com/GoogleCloudPlatform/cloudsql-proxy/proxy/dialers/mysql"
	// gorm mysql dialect init registration
	// also needed for GCP Cloud SQL Proxy
	_ "github.com/jinzhu/gorm/dialects/mysql"
)

type mysqlDB struct {
	logger logrus.FieldLogger
}

func (my mysqlDB) connect(ctx context.Context, cfg *sqlcommon.Configuration, isReadOnly bool) (db *gorm.DB, version string, supportsCTE bool, err error) {
	mysqlConfig, err := sqlcommon.ConfigureMySQLConnection(cfg, isReadOnly)
	if err != nil {
		return nil, "", false, err
	}

	var errOpen error
	switch {
	case cfg.DBTypeConfig.AWSMySQL != nil:
		dsn, err := sqlcommon.BuildAWSMySQLDSN(cfg, mysqlConfig)
		if err != nil {
			return nil, "", false, err
		}
		db, errOpen = gorm.Open(awsrds.MySQLDriverName, dsn)
	case cfg.DBTypeConfig.AzureMySQL != nil:
		if mysqlConfig.Passwd != "" {
			return nil, "", false, errors.New("invalid mysql configuration: password should not be set when using Microsoft Entra ID authentication")
		}

		resolved, err := cfg.DBTypeConfig.AzureMySQL.Resolve()
		if err != nil {
			return nil, "", false, err
		}

		azurerdsConfig := &azurerds.Config{
			AuthType:                  resolved.AuthType,
			TenantID:                  resolved.TenantID,
			ClientID:                  resolved.ClientID,
			ClientSecret:              resolved.ClientSecret,
			ClientCertificatePath:     resolved.ClientCertificatePath,
			ClientCertificatePassword: resolved.ClientCertificatePassword,
			SendCertificateChain:      resolved.SendCertificateChain,
			FederatedTokenFile:        resolved.FederatedTokenFile,
			ManagedIdentityResourceID: resolved.ManagedIdentityResourceID,
			DriverName:                azurerds.MySQLDriverName,
			ConnString:                mysqlConfig.FormatDSN(),
		}

		dsn, err := azurerdsConfig.FormatDSN()
		if err != nil {
			return nil, "", false, err
		}
		db, errOpen = gorm.Open(azurerds.MySQLDriverName, dsn)
	default:
		db, errOpen = gorm.Open("mysql", mysqlConfig.FormatDSN())
	}

	if errOpen != nil {
		return nil, "", false, errOpen
	}

	version, err = queryVersion(ctx, db, sqlcommon.MySQLVersionQuery)
	if err != nil {
		return nil, "", false, err
	}

	if strings.HasPrefix(version, "5.7.") {
		my.logger.Warn("MySQL 5.7 is no longer officially supported, and SPIRE does not guarantee compatibility with MySQL 5.7. Consider upgrading to a newer version of MySQL.")
	}

	supportsCTE, err = my.supportsCTE(ctx, db)
	if err != nil {
		return nil, "", false, err
	}

	return db, version, supportsCTE, nil
}

func (my mysqlDB) supportsCTE(ctx context.Context, gormDB *gorm.DB) (bool, error) {
	db := gormDB.DB()
	if db == nil {
		return false, errors.New("unable to get raw database object")
	}
	var value int64
	err := db.QueryRowContext(ctx, "WITH a AS (SELECT 1 AS v) SELECT * FROM a;").Scan(&value)
	switch {
	case err == nil:
		return true, nil
	case my.isParseError(err):
		return false, nil
	default:
		return false, err
	}
}

func (my mysqlDB) isParseError(err error) bool {
	var e *mysql.MySQLError
	ok := errors.As(err, &e)
	return ok && e.Number == 1064 // ER_PARSE_ERROR
}

func (my mysqlDB) isConstraintViolation(err error) bool {
	return sqlcommon.IsMySQLConstraintViolation(err)
}
