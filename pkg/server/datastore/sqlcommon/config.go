package sqlcommon

import (
	"github.com/hashicorp/hcl/hcl/ast"
)

// Configuration for the sql datastore implementation.
// Pointer values are used to distinguish between "unset" and "zero" values.
type Configuration struct {
	DatabaseTypeNode   ast.Node `hcl:"database_type" json:"database_type"`
	ConnectionString   string   `hcl:"connection_string" json:"connection_string"`
	RoConnectionString string   `hcl:"ro_connection_string" json:"ro_connection_string"`
	RootCAPath         string   `hcl:"root_ca_path" json:"root_ca_path"`
	ClientCertPath     string   `hcl:"client_cert_path" json:"client_cert_path"`
	ClientKeyPath      string   `hcl:"client_key_path" json:"client_key_path"`
	ConnMaxLifetime    *string  `hcl:"conn_max_lifetime" json:"conn_max_lifetime"`
	MaxOpenConns       *int     `hcl:"max_open_conns" json:"max_open_conns"`
	MaxIdleConns       *int     `hcl:"max_idle_conns" json:"max_idle_conns"`
	DisableMigration   bool     `hcl:"disable_migration" json:"disable_migration"`

	DBTypeConfig *DBTypeConfig
	// Undocumented flags
	LogSQL bool `hcl:"log_sql" json:"log_sql"`
}

type DBTypeConfig struct {
	AWSMySQL     *AWSConfig `hcl:"aws_mysql" json:"aws_mysql"`
	AWSPostgres  *AWSConfig `hcl:"aws_postgres" json:"aws_postgres"`
	DatabaseType string
}

type AWSConfig struct {
	Region          string `hcl:"region"`
	AccessKeyID     string `hcl:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key"`
}

func (a *AWSConfig) Validate() error {
	if a.Region == "" {
		return NewSQLError("region must be specified")
	}
	return nil
}

// GetConnectionString returns the connection string corresponding to the database connection.
func GetConnectionString(cfg *Configuration, isReadOnly bool) string {
	connectionString := cfg.ConnectionString
	if isReadOnly {
		connectionString = cfg.RoConnectionString
	}
	return connectionString
}
