package sqlcommon

import (
	"errors"
	"fmt"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/spiffe/spire/pkg/server/datastore/sqldriver/awsrds"
)

// BuildAWSPostgresDSN builds the AWS RDS / IAM DSN for a postgres connection.
// It rejects a connection string carrying a password, since IAM auth supplies
// a rotating token instead. Shared by the v1 and v2 datastores so IAM DSN
// handling has a single source of truth.
func BuildAWSPostgresDSN(cfg *Configuration) (string, error) {
	connString := GetConnectionString(cfg, false)
	c, err := pgx.ParseConfig(connString)
	if err != nil {
		return "", err
	}
	if c.Password != "" {
		return "", errors.New("invalid postgres configuration: password should not be set when using IAM authentication")
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
	return awsrdsConfig.FormatDSN()
}

// BuildAWSMySQLDSN builds the AWS RDS / IAM DSN for a MySQL connection.
func BuildAWSMySQLDSN(cfg *Configuration, mysqlConfig *mysql.Config) (string, error) {
	if mysqlConfig.Passwd != "" {
		return "", errors.New("invalid mysql configuration: password should not be set when using IAM authentication")
	}

	awsrdsConfig := &awsrds.Config{
		Region:          cfg.DBTypeConfig.AWSMySQL.Region,
		AccessKeyID:     cfg.DBTypeConfig.AWSMySQL.AccessKeyID,
		SecretAccessKey: cfg.DBTypeConfig.AWSMySQL.SecretAccessKey,
		Endpoint:        mysqlConfig.Addr,
		DbUser:          mysqlConfig.User,
		DriverName:      awsrds.MySQLDriverName,
		ConnString:      mysqlConfig.FormatDSN(),
	}
	return awsrdsConfig.FormatDSN()
}
