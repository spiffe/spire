package sqlcommon

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/printer"
)

const (
	// MySQL database type
	MySQL = "mysql"
	// PostgreSQL database type
	PostgreSQL = "postgres"
	// SQLite database type
	SQLite = "sqlite3"
	// AWSMySQL is a MySQL database provided by an AWS service
	AWSMySQL = "aws_mysql"
	// AWSPostgreSQL is a PostgreSQL database provided by an AWS service
	AWSPostgreSQL = "aws_postgres"
)

// IsMySQLDbType reports whether dbType is a MySQL-family database type.
func IsMySQLDbType(dbType string) bool {
	return dbType == MySQL || dbType == AWSMySQL
}

// IsPostgresDbType reports whether dbType is a PostgreSQL-family database type.
func IsPostgresDbType(dbType string) bool {
	return dbType == PostgreSQL || dbType == AWSPostgreSQL
}

// IsSQLiteDbType reports whether dbType is the SQLite database type.
func IsSQLiteDbType(dbType string) bool {
	return dbType == SQLite
}

// BuildConfig decodes the HCL datastore configuration and resolves the
// database_type node into a DBTypeConfig.
func BuildConfig(hclConfiguration string) (*Configuration, error) {
	config := &Configuration{}
	if err := hcl.Decode(config, hclConfiguration); err != nil {
		return nil, err
	}

	dbTypeConfig, err := ParseDatabaseTypeASTNode(config.DatabaseTypeNode)
	if err != nil {
		return nil, err
	}

	config.DBTypeConfig = dbTypeConfig
	return config, nil
}

// ParseDatabaseTypeASTNode resolves the database_type HCL node, which may be
// either a bare string ("sqlite3") or an object block (aws_mysql/aws_postgres).
func ParseDatabaseTypeASTNode(node ast.Node) (*DBTypeConfig, error) {
	lt, ok := node.(*ast.LiteralType)
	if ok {
		return &DBTypeConfig{DatabaseType: strings.Trim(lt.Token.Text, "\"")}, nil
	}

	objectList, ok := node.(*ast.ObjectList)
	if !ok {
		return nil, errors.New("malformed database type configuration")
	}

	if len(objectList.Items) != 1 {
		return nil, errors.New("exactly one database type is expected")
	}

	if len(objectList.Items[0].Keys) != 1 {
		return nil, errors.New("exactly one key is expected")
	}

	var data bytes.Buffer
	if err := printer.DefaultConfig.Fprint(&data, node); err != nil {
		return nil, err
	}

	dbTypeConfig := new(DBTypeConfig)
	if err := hcl.Decode(dbTypeConfig, data.String()); err != nil {
		return nil, fmt.Errorf("failed to decode configuration: %w", err)
	}

	databaseType := strings.Trim(objectList.Items[0].Keys[0].Token.Text, "\"")
	switch databaseType {
	case AWSMySQL:
	case AWSPostgreSQL:
	default:
		return nil, fmt.Errorf("unknown database type: %s", databaseType)
	}

	dbTypeConfig.DatabaseType = databaseType
	return dbTypeConfig, nil
}

// ConfigValidate performs static validation of a decoded datastore config.
func ConfigValidate(cfg *Configuration) error {
	if cfg.DBTypeConfig.DatabaseType == "" {
		return NewSQLError("database_type must be set")
	}

	if cfg.ConnectionString == "" {
		return NewSQLError("connection_string must be set")
	}

	if IsMySQLDbType(cfg.DBTypeConfig.DatabaseType) {
		if err := ValidateMySQLConfig(cfg, false); err != nil {
			return err
		}

		if cfg.RoConnectionString != "" {
			if err := ValidateMySQLConfig(cfg, true); err != nil {
				return err
			}
		}
	}

	if cfg.DBTypeConfig.AWSMySQL != nil {
		if err := cfg.DBTypeConfig.AWSMySQL.Validate(); err != nil {
			return err
		}
	}

	if cfg.DBTypeConfig.AWSPostgres != nil {
		if err := cfg.DBTypeConfig.AWSPostgres.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// ValidateMySQLConfig ensures the MySQL connection string requests parseTime.
func ValidateMySQLConfig(cfg *Configuration, isReadOnly bool) error {
	opts, err := mysql.ParseDSN(GetConnectionString(cfg, isReadOnly))
	if err != nil {
		return NewWrappedSQLError(err)
	}

	if !opts.ParseTime {
		return NewSQLError("invalid mysql config: missing parseTime=true param in connection_string")
	}

	return nil
}
