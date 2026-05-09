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
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugindecode"
	"go.yaml.in/yaml/v3"
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
	// AzurePostgreSQL is a PostgreSQL database provided by an Azure service,
	// authenticated using Microsoft Entra ID (Azure AD)
	AzurePostgreSQL = "azure_postgres"
	// AzureMySQL is a MySQL database provided by an Azure service,
	// authenticated using Microsoft Entra ID (Azure AD)
	AzureMySQL = "azure_mysql"
)

// IsMySQLDbType reports whether dbType is a MySQL-family database type.
func IsMySQLDbType(dbType string) bool {
	return dbType == MySQL || dbType == AWSMySQL || dbType == AzureMySQL
}

// IsPostgresDbType reports whether dbType is a PostgreSQL-family database type.
func IsPostgresDbType(dbType string) bool {
	return dbType == PostgreSQL || dbType == AWSPostgreSQL || dbType == AzurePostgreSQL
}

// IsSQLiteDbType reports whether dbType is the SQLite database type.
func IsSQLiteDbType(dbType string) bool {
	return dbType == SQLite
}

// BuildConfig decodes the datastore configuration and resolves the
// database_type node into a DBTypeConfig.
func BuildConfig(configuration string, format catalog.ConfigFormat) (*Configuration, error) {
	config := &Configuration{}
	if err := plugindecode.DecodeConfig(configuration, format, config); err != nil {
		return nil, err
	}

	if format == catalog.ConfigFormatYAML {
		config.DBTypeConfig = &DBTypeConfig{}
		if config.DatabaseTypeYAML != nil {
			config.DBTypeConfig = &config.DatabaseTypeYAML.DBTypeConfig
		}
		return config, nil
	}

	dbTypeConfig, err := ParseDatabaseTypeASTNode(config.DatabaseTypeNode)
	if err != nil {
		return nil, err
	}

	config.DBTypeConfig = dbTypeConfig
	return config, nil
}

// ParseDatabaseTypeASTNode resolves the database_type HCL node, which may be
// either a bare string ("sqlite3") or an object block (aws_mysql, aws_postgres, azure_mysql, azure_postgres).
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
	case AzurePostgreSQL:
	case AzureMySQL:
	default:
		return nil, fmt.Errorf("unknown database type: %s", databaseType)
	}

	dbTypeConfig.DatabaseType = databaseType
	return dbTypeConfig, nil
}

// DatabaseTypeYAML is the YAML form of database_type: either a scalar such as
// "sqlite3", or a mapping with a single key such as "awsPostgres".
type DatabaseTypeYAML struct {
	DBTypeConfig
}

func (d *DatabaseTypeYAML) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		d.DatabaseType = node.Value
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return errors.New("malformed database type configuration")
	}
	if len(node.Content) != 2 {
		return errors.New("exactly one database type is expected")
	}

	key := node.Content[0].Value
	databaseType, ok := map[string]string{
		"awsMysql":      AWSMySQL,
		"awsPostgres":   AWSPostgreSQL,
		"azureMysql":    AzureMySQL,
		"azurePostgres": AzurePostgreSQL,
	}[key]
	if !ok {
		return fmt.Errorf("unknown database type: %s", key)
	}
	if err := plugindecode.DecodeYAMLNode(node, &d.DBTypeConfig); err != nil {
		return fmt.Errorf("failed to decode configuration: %w", err)
	}
	d.DatabaseType = databaseType
	return nil
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

	if cfg.DBTypeConfig.AzurePostgres != nil {
		if err := cfg.DBTypeConfig.AzurePostgres.Validate(); err != nil {
			return err
		}
	}

	if cfg.DBTypeConfig.AzureMySQL != nil {
		if err := cfg.DBTypeConfig.AzureMySQL.Validate(); err != nil {
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
