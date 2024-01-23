package awsrds

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jinzhu/gorm"
	"github.com/lib/pq"
)

const (
	MySQLDriverName    = "aws-rds-mysql"
	PostgresDriverName = "aws-rds-postgres"
	iso8601BasicFormat = "20060102T150405Z"
	timeOut            = time.Second * 30
)

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
	nowFunc      func() time.Time
}

// Open is the overridden method for opening a connection, using
// AWS IAM authentication
func (w *sqlDriverWrapper) Open(name string) (driver.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeOut)
	defer cancel()

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
		token = &authToken{
			nowFunc: w.nowFunc,
		}
		w.tokensMap[name] = token
	}
	password, err := token.getAWSAuthToken(ctx, config, w.tokenBuilder)
	if err != nil {
		return nil, fmt.Errorf("could not get authorization token: %w", err)
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
		return "", errors.New("password was provided in the connection string")
	}
	return fmt.Sprintf("%s password=%s", connString, password), nil
}

func addPasswordToMySQLConnString(connString, password string) (string, error) {
	cfg, err := mysql.ParseDSN(connString)
	if err != nil {
		return "", fmt.Errorf("could not parse connection string: %w", err)
	}

	if cfg.Passwd != "" {
		return "", errors.New("password was provided in the connection string")
	}

	cfg.Passwd = password
	return cfg.FormatDSN(), nil
}

func init() {
	registerPostgres()
	registerMySQL()
}

func newAWSClientConfig(ctx context.Context, c *Config) (aws.Config, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(c.Region),
	)
	if err != nil {
		return aws.Config{}, err
	}

	if c.SecretAccessKey != "" && c.AccessKeyID != "" {
		cfg.Credentials = credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, "")
	}

	return cfg, nil
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
