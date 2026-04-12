package sqlstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/datastore/sqldriver/awsrds"

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

const (
	tlsConfigName = "spireCustomTLS"
)

func (my mysqlDB) connect(ctx context.Context, cfg *configuration, isReadOnly bool) (db *gorm.DB, version string, supportsCTE bool, err error) {
	mysqlConfig, err := configureConnection(cfg, isReadOnly)
	if err != nil {
		return nil, "", false, err
	}

	var errOpen error
	switch {
	case cfg.databaseTypeConfig.AWSMySQL != nil:
		awsrdsConfig := &awsrds.Config{
			Region:          cfg.databaseTypeConfig.AWSMySQL.Region,
			AccessKeyID:     cfg.databaseTypeConfig.AWSMySQL.AccessKeyID,
			SecretAccessKey: cfg.databaseTypeConfig.AWSMySQL.SecretAccessKey,
			Endpoint:        mysqlConfig.Addr,
			DbUser:          mysqlConfig.User,
			DriverName:      awsrds.MySQLDriverName,
			ConnString:      mysqlConfig.FormatDSN(),
		}

		dsn, err := awsrdsConfig.FormatDSN()
		if err != nil {
			return nil, "", false, err
		}
		db, errOpen = gorm.Open(awsrds.MySQLDriverName, dsn)
	default:
		db, errOpen = gorm.Open("mysql", mysqlConfig.FormatDSN())
	}

	if errOpen != nil {
		return nil, "", false, errOpen
	}

	version, err = queryVersion(ctx, db, "SELECT VERSION()")
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
	var e *mysql.MySQLError
	ok := errors.As(err, &e)
	return ok && e.Number == 1062 // ER_DUP_ENTRY
}

// configureConnection modifies the connection string to support features that
// normally require code changes, like custom Root CAs or client certificates
func configureConnection(cfg *configuration, isReadOnly bool) (*mysql.Config, error) {
	connectionString := getConnectionString(cfg, isReadOnly)
	mysqlConfig, err := mysql.ParseDSN(connectionString)
	if err != nil {
		// the connection string should have already been validated by now
		// (in validateMySQLConfig)
		return nil, err
	}

	if !hasTLSConfig(cfg) {
		// connection string doesn't have to be modified
		return mysqlConfig, nil
	}

	// MySQL still allows, and in some places requires, older TLS versions. For example, when built with yaSSL, it is limited to TLSv1 and TLSv1.1.
	// TODO: consider making this more secure by default
	tlsConf := tls.Config{} //nolint: gosec // see above

	// load and configure Root CA if it exists
	if len(cfg.RootCAPath) > 0 {
		rootCertPool := x509.NewCertPool()
		pem, err := os.ReadFile(cfg.RootCAPath)
		if err != nil {
			return nil, errors.New("invalid mysql config: cannot find Root CA defined in root_ca_path")
		}

		if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
			return nil, errors.New("invalid mysql config: failed to parse Root CA defined in root_ca_path")
		}
		tlsConf.RootCAs = rootCertPool
	}

	// load and configure client certificate if it exists
	if len(cfg.ClientCertPath) > 0 && len(cfg.ClientKeyPath) > 0 {
		clientCert := make([]tls.Certificate, 0, 1)
		certs, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
		if err != nil {
			return nil, errors.New("invalid mysql config: failed to load client certificate defined in client_cert_path and client_key_path")
		}
		clientCert = append(clientCert, certs)
		tlsConf.Certificates = clientCert
	}

	// register a custom TLS config that uses custom Root CAs with the MySQL driver
	if err := mysql.RegisterTLSConfig(tlsConfigName, &tlsConf); err != nil {
		return nil, errors.New("failed to register mysql TLS config")
	}

	// instruct MySQL driver to use the custom TLS config
	mysqlConfig.TLSConfig = tlsConfigName

	return mysqlConfig, nil
}

func hasTLSConfig(cfg *configuration) bool {
	return len(cfg.RootCAPath) > 0 || len(cfg.ClientCertPath) > 0 && len(cfg.ClientKeyPath) > 0
}

func validateMySQLConfig(cfg *configuration, isReadOnly bool) error {
	opts, err := mysql.ParseDSN(getConnectionString(cfg, isReadOnly))
	if err != nil {
		return newWrappedSQLError(err)
	}

	if !opts.ParseTime {
		return newSQLError("invalid mysql config: missing parseTime=true param in connection_string")
	}

	return nil
}
