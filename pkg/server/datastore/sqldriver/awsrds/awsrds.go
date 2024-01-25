package awsrds

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jinzhu/gorm"
	"github.com/lib/pq"
)

const (
	MySQLDriverName     = "aws-rds-mysql"
	PostgresDriverName  = "aws-rds-postgres"
	getAuthTokenTimeout = time.Second * 30
)

// nowFunc returns the current time and can overridden in tests.
var nowFunc = time.Now

// Config holds the configuration settings to be able to authenticate to a
// database in the AWS RDS service.
type Config struct {
	Region          string `json:"region"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	Endpoint        string `json:"endpoint"`
	DbUser          string `json:"dbuser"`
	DriverName      string `json:"driver_name"`
	ConnString      string `json:"conn_string"`
}

// FormatDSN returns a DSN string based on the configuration.
func (c *Config) FormatDSN() (string, error) {
	dsn, err := json.Marshal(c)

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

type tokens map[string]tokenGetter

// sqlDriverWrapper is a wrapper for SQL drivers, adding IAM authentication.
type sqlDriverWrapper struct {
	sqlDriver    driver.Driver
	tokenBuilder authTokenBuilder
	tokensMap    tokens
}

// Open is the overridden method for opening a connection, using
// AWS IAM authentication
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

	token, ok := w.tokensMap[name]
	if !ok {
		token = &authToken{}
		w.tokensMap[name] = token
	}

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
		return "", errors.New("unexpected password in connection string for IAM authentication")
	}
	return fmt.Sprintf("%s password=%s", connString, password), nil
}

func addPasswordToMySQLConnString(connString, password string) (string, error) {
	cfg, err := mysql.ParseDSN(connString)
	if err != nil {
		return "", fmt.Errorf("could not parse connection string: %w", err)
	}

	if cfg.Passwd != "" {
		return "", errors.New("unexpected password in connection string for IAM authentication")
	}

	cfg.Passwd = password
	return cfg.FormatDSN(), nil
}

func init() {
	registerPostgres()
	registerMySQL()
}

func registerPostgres() {
	d, ok := gorm.GetDialect("postgres")
	if !ok {
		panic("could not find postgres dialect")
	}

	gorm.RegisterDialect(PostgresDriverName, d)
	sql.Register(PostgresDriverName, &sqlDriverWrapper{
		sqlDriver:    &pq.Driver{},
		tokenBuilder: &awsTokenBuilder{},
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
		tokenBuilder: &awsTokenBuilder{},
		tokensMap:    make(tokens),
	})
}
