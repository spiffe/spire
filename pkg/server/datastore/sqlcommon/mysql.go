package sqlcommon

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"

	"github.com/go-sql-driver/mysql"
)

// TLSConfigName is the key under which the custom MySQL TLS config is
// registered with the go-sql-driver/mysql driver.
const TLSConfigName = "spireCustomTLS"

// HasTLSConfig reports whether the configuration requests custom TLS material
// (a custom Root CA and/or a client certificate/key pair).
func HasTLSConfig(cfg *Configuration) bool {
	return len(cfg.RootCAPath) > 0 || len(cfg.ClientCertPath) > 0 && len(cfg.ClientKeyPath) > 0
}

// ConfigureMySQLConnection parses the connection string into a *mysql.Config
// and, when custom TLS material is configured (root_ca_path / client_cert_path
// / client_key_path), builds and registers a custom tls.Config with the
// go-sql-driver/mysql driver and points the returned config at it. Shared by
// the v1 and v2 datastores so custom-CA / mutual-TLS handling has a single
// source of truth. The connection string must already have been validated by
// ValidateMySQLConfig.
func ConfigureMySQLConnection(cfg *Configuration, isReadOnly bool) (*mysql.Config, error) {
	connectionString := GetConnectionString(cfg, isReadOnly)
	mysqlConfig, err := mysql.ParseDSN(connectionString)
	if err != nil {
		return nil, err
	}

	if !HasTLSConfig(cfg) {
		// connection string doesn't have to be modified
		return mysqlConfig, nil
	}

	var tlsConf tls.Config

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
	if err := mysql.RegisterTLSConfig(TLSConfigName, &tlsConf); err != nil {
		return nil, errors.New("failed to register mysql TLS config")
	}

	// instruct MySQL driver to use the custom TLS config
	mysqlConfig.TLSConfig = TLSConfigName

	return mysqlConfig, nil
}
