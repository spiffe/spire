package sql

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"

	// gorm mysql `cloudsql` dialect, for GCP
	// Cloud SQL Proxy
	_ "github.com/GoogleCloudPlatform/cloudsql-proxy/proxy/dialers/mysql"
	// gorm mysql dialect init registration
	// also needed for GCP Cloud SQL Proxy
	_ "github.com/jinzhu/gorm/dialects/mysql"
	_ "github.com/spiffe/spire/pkg/server/plugin/datastore"
)

type mysql struct{}

const (
	tlsConfigName = "spireCustomTLS"
)

func (my mysql) connect(cfg *configuration, isReadOnly bool) (*gorm.DB, error) {
	connString, err := configureConnection(cfg, isReadOnly)
	if err != nil {
		return nil, err
	}

	db, err := gorm.Open("mysql", connString)
	if err != nil {
		return nil, err
	}
	return db, nil
}

// configureConnection modifies the connection string to support features that
// normally require code changes, like custom Root CAs or client certificates
func configureConnection(cfg *configuration, isReadOnly bool) (string, error) {
	connectionString := getConnectionString(cfg, isReadOnly)
	if !hasTLSConfig(cfg) {
		// connection string doesn't have to be modified
		return connectionString, nil
	}

	tlsConf := tls.Config{}

	opts, err := mysqldriver.ParseDSN(connectionString)
	if err != nil {
		// the connection string should have already been validated by now
		// (in validateMySQLConfig)
		return "", sqlError.Wrap(err)
	}

	// load and configure Root CA if it exists
	if len(cfg.RootCAPath) > 0 {
		rootCertPool := x509.NewCertPool()
		pem, err := ioutil.ReadFile(cfg.RootCAPath)

		if err != nil {
			return "", sqlError.New("invalid mysql config: cannot find Root CA defined in root_ca_path")
		}

		if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
			return "", sqlError.New("invalid mysql config: failed to parse Root CA defined in root_ca_path")
		}
		tlsConf.RootCAs = rootCertPool
	}

	// load and configure client certificate if it exists
	if len(cfg.ClientCertPath) > 0 && len(cfg.ClientKeyPath) > 0 {
		clientCert := make([]tls.Certificate, 0, 1)
		certs, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
		if err != nil {
			return "", sqlError.New("invalid mysql config: failed to load client certificate defined in client_cert_path and client_key_path")
		}
		clientCert = append(clientCert, certs)
		tlsConf.Certificates = clientCert
	}

	// register a custom TLS config that uses custom Root CAs with the MySQL driver
	if err := mysqldriver.RegisterTLSConfig(tlsConfigName, &tlsConf); err != nil {
		return "", sqlError.New("failed to register mysql TLS config")
	}

	// instruct MySQL driver to use the custom TLS config
	opts.TLSConfig = tlsConfigName

	return opts.FormatDSN(), nil
}

func hasTLSConfig(cfg *configuration) bool {
	return len(cfg.RootCAPath) > 0 || len(cfg.ClientCertPath) > 0 && len(cfg.ClientKeyPath) > 0
}

func validateMySQLConfig(cfg *configuration, isReadOnly bool) error {
	opts, err := mysqldriver.ParseDSN(getConnectionString(cfg, isReadOnly))
	if err != nil {
		return sqlError.Wrap(err)
	}

	if !opts.ParseTime {
		return sqlError.Wrap(errors.New("invalid mysql config: missing parseTime=true param in connection_string"))
	}

	return nil
}
