// Package azurerds implements a SQL driver wrapper that authenticates to
// Azure Database for PostgreSQL and Azure Database for MySQL using a
// Microsoft Entra ID (Azure AD) access token instead of a static password.
package azurerds

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jinzhu/gorm"
	"github.com/lib/pq"
)

const (
	MySQLDriverName    = "azure-rds-mysql"
	PostgresDriverName = "azure-rds-postgres"

	getAuthTokenTimeout = time.Second * 30
)

// Supported values for Config.AuthType.
const (
	AuthTypeClientSecret          = "client_secret"
	AuthTypeClientCertificate     = "client_certificate"
	AuthTypeWorkloadIdentity      = "workload_identity"
	AuthTypeSystemManagedIdentity = "system_managed_identity"
	AuthTypeUserManagedIdentity   = "user_managed_identity"
)

// Config holds the configuration settings needed to authenticate to Azure
// Database for PostgreSQL or Azure Database for MySQL using a Microsoft
// Entra ID access token. It is expected to already be fully resolved (e.g.
// via sqlcommon.AzureConfig.Resolve) so every field required by AuthType is
// populated.
type Config struct {
	AuthType string `json:"auth_type"`

	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`

	ClientCertificatePath     string `json:"client_certificate_path"`
	ClientCertificatePassword string `json:"client_certificate_password"`
	SendCertificateChain      bool   `json:"send_certificate_chain"`

	FederatedTokenFile string `json:"federated_token_file"`

	ManagedIdentityResourceID string `json:"managed_identity_resource_id"`

	DriverName string `json:"driver_name"`
	ConnString string `json:"conn_string"`
}

func init() {
	registerPostgres()
	registerMySQL()
}

// FormatDSN returns a DSN string based on the configuration.
func (c *Config) FormatDSN() (string, error) {
	dsn, err := json.Marshal(c) //nolint: gosec // internal driver DSN, never logged
	if err != nil {
		return "", fmt.Errorf("could not format DSN: %w", err)
	}

	return string(dsn), nil
}

func (c *Config) getConnStringWithPassword(password string) (string, error) {
	switch c.DriverName {
	case MySQLDriverName:
		return addPasswordToMySQLConnString(c.ConnString, password)
	case PostgresDriverName:
		return addPasswordToPostgresConnString(c.ConnString, password)
	case "":
		return "", errors.New("missing driver name")
	default:
		return "", fmt.Errorf("driver %q is not supported", c.DriverName)
	}
}

type tokens map[string]*authToken

// sqlDriverWrapper is a wrapper for SQL drivers, adding Microsoft Entra ID
// authentication.
type sqlDriverWrapper struct {
	sqlDriver    driver.Driver
	tokenBuilder authTokenBuilder

	tokensMapMtx sync.Mutex
	tokensMap    tokens
}

// Open is the overridden method for opening a connection, using Microsoft
// Entra ID authentication.
func (w *sqlDriverWrapper) Open(name string) (driver.Conn, error) {
	if w.sqlDriver == nil {
		return nil, errors.New("missing sql driver")
	}

	if w.tokenBuilder == nil {
		return nil, errors.New("missing token builder")
	}

	config := new(Config)
	if err := json.Unmarshal([]byte(name), config); err != nil {
		return nil, fmt.Errorf("could not unmarshal configuration: %w", err)
	}

	w.tokensMapMtx.Lock()
	token, ok := w.tokensMap[name]
	if !ok {
		token = &authToken{}
		w.tokensMap[name] = token
	}
	w.tokensMapMtx.Unlock()

	// We need a context for getting the authentication token. Since there is no
	// parent context to derive from, we create a context with a timeout to
	// get the authentication token.
	ctx, cancel := context.WithTimeout(context.Background(), getAuthTokenTimeout)
	defer cancel()
	password, err := token.getAuthToken(ctx, config, w.tokenBuilder)
	if err != nil {
		return nil, fmt.Errorf("could not get authentication token: %w", err)
	}

	connStringWithPassword, err := config.getConnStringWithPassword(password)
	if err != nil {
		return nil, err
	}

	return w.sqlDriver.Open(connStringWithPassword)
}

func addPasswordToPostgresConnString(connString, password string) (string, error) {
	cfg, err := pgx.ParseConfig(connString)
	if err != nil {
		return "", fmt.Errorf("could not parse connection string: %w", err)
	}
	if cfg.Password != "" {
		return "", errors.New("unexpected password in connection string for Microsoft Entra ID authentication")
	}
	return fmt.Sprintf("%s password='%s'", connString, escapeSpecialCharsPostgres(password)), nil
}

// escapeSpecialCharsPostgres escapes special characters within a value of a
// keyword/value postgres connection string.
// Single quotes and backslashes within a value must be escaped with a
// backslash, i.e., \' and \\.
func escapeSpecialCharsPostgres(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `'`, `\'`)
}

func addPasswordToMySQLConnString(connString, password string) (string, error) {
	cfg, err := mysql.ParseDSN(connString)
	if err != nil {
		return "", fmt.Errorf("could not parse connection string: %w", err)
	}

	if cfg.Passwd != "" {
		return "", errors.New("unexpected password in connection string for Microsoft Entra ID authentication")
	}

	cfg.Passwd = password
	return cfg.FormatDSN(), nil
}

func registerPostgres() {
	d, ok := gorm.GetDialect("postgres")
	if !ok {
		panic("could not find postgres dialect")
	}

	gorm.RegisterDialect(PostgresDriverName, d)
	sql.Register(PostgresDriverName, &sqlDriverWrapper{
		sqlDriver:    &pq.Driver{},
		tokenBuilder: &azureTokenBuilder{},
		tokensMap:    make(tokens),
	})
}

func registerMySQL() {
	d, ok := gorm.GetDialect("mysql")
	if !ok {
		panic("could not find mysql dialect")
	}

	gorm.RegisterDialect(MySQLDriverName, d)
	sql.Register(MySQLDriverName, &sqlDriverWrapper{
		sqlDriver:    &mysql.MySQLDriver{},
		tokenBuilder: &azureTokenBuilder{},
		tokensMap:    make(tokens),
	})
}
