package sqlcommon

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/stretchr/testify/require"
)

func TestBuildConfigSQLite(t *testing.T) {
	cfg, err := BuildConfig(`
		database_type = "sqlite3"
		connection_string = "file:test.db"
	`, catalog.ConfigFormatHCL)
	require.NoError(t, err)
	require.Equal(t, SQLite, cfg.DBTypeConfig.DatabaseType)
	require.Equal(t, "file:test.db", cfg.ConnectionString)
	require.NoError(t, ConfigValidate(cfg))
}

func TestBuildConfigAWSPostgres(t *testing.T) {
	cfg, err := BuildConfig(`
		database_type "aws_postgres" {
			region = "us-west-2"
			access_key_id = "AKID"
			secret_access_key = "SECRET"
		}
		connection_string = "postgres://host:5432/db"
	`, catalog.ConfigFormatHCL)
	require.NoError(t, err)
	require.Equal(t, AWSPostgreSQL, cfg.DBTypeConfig.DatabaseType)
	require.NotNil(t, cfg.DBTypeConfig.AWSPostgres)
	require.Equal(t, "us-west-2", cfg.DBTypeConfig.AWSPostgres.Region)
	require.NoError(t, ConfigValidate(cfg))
}

func TestBuildConfigAzure(t *testing.T) {
	for _, databaseType := range []string{AzurePostgreSQL, AzureMySQL} {
		t.Run(databaseType, func(t *testing.T) {
			cfg, err := BuildConfig(`
				database_type "`+databaseType+`" {
					auth_type = "system_managed_identity"
				}
				connection_string = "user@tcp(host:3306)/db?parseTime=true"
			`, catalog.ConfigFormatHCL)
			require.NoError(t, err)
			require.Equal(t, databaseType, cfg.DBTypeConfig.DatabaseType)
			require.NoError(t, ConfigValidate(cfg))
		})
	}
}

func TestBuildConfigYAML(t *testing.T) {
	cfg, err := BuildConfig(`
database_type: sqlite3
connection_string: file:test.db
max_open_conns: 5
`, catalog.ConfigFormatYAML)
	require.NoError(t, err)
	require.Equal(t, SQLite, cfg.DBTypeConfig.DatabaseType)
	require.Equal(t, "file:test.db", cfg.ConnectionString)
	require.Equal(t, 5, *cfg.MaxOpenConns)
	require.NoError(t, ConfigValidate(cfg))

	cfg, err = BuildConfig(`
database_type:
  aws_postgres:
    region: us-west-2
    access_key_id: AKID
connection_string: postgres://host:5432/db
`, catalog.ConfigFormatYAML)
	require.NoError(t, err)
	require.Equal(t, AWSPostgreSQL, cfg.DBTypeConfig.DatabaseType)
	require.Equal(t, "us-west-2", cfg.DBTypeConfig.AWSPostgres.Region)
	require.Equal(t, "AKID", cfg.DBTypeConfig.AWSPostgres.AccessKeyID)
	require.NoError(t, ConfigValidate(cfg))

	cfg, err = BuildConfig(`
database_type:
  azure_mysql:
    auth_type: system_managed_identity
connection_string: user@tcp(host:3306)/db?parseTime=true
`, catalog.ConfigFormatYAML)
	require.NoError(t, err)
	require.Equal(t, AzureMySQL, cfg.DBTypeConfig.DatabaseType)
	require.NoError(t, ConfigValidate(cfg))

	cfg, err = BuildConfig("connection_string: file:test.db\n", catalog.ConfigFormatYAML)
	require.NoError(t, err)
	require.EqualError(t, ConfigValidate(cfg), "datastore-sql: database_type must be set")
}

func TestBuildConfigYAMLErrors(t *testing.T) {
	for _, tt := range []struct {
		name, config, err string
	}{
		{"unknown type", "database_type:\n  oracle: {}\n", "unknown database type: oracle"},
		{"two types", "database_type:\n  aws_mysql: {}\n  aws_postgres: {}\n", "exactly one database type is expected"},
		{"null options", "database_type:\n  aws_postgres:\n", "aws_postgres options must be a mapping; use {} for no options"},
		{"unknown nested key", "database_type:\n  aws_mysql:\n    regoin: x\n", "field regoin not found"},
		{"camelCase key", "connectionString: x\n", "field connectionString not found"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildConfig(tt.config, catalog.ConfigFormatYAML)
			require.ErrorContains(t, err, tt.err)
		})
	}
}

func TestConfigValidateAzureAuthType(t *testing.T) {
	cfg, err := BuildConfig(`
		database_type "azure_postgres" {
			auth_type = "unknown"
		}
		connection_string = "postgres://host:5432/db"
	`, catalog.ConfigFormatHCL)
	require.NoError(t, err)
	require.Error(t, ConfigValidate(cfg))
}

func TestConfigValidateErrors(t *testing.T) {
	// database_type unset
	err := ConfigValidate(&Configuration{DBTypeConfig: &DBTypeConfig{}})
	require.EqualError(t, err, "datastore-sql: database_type must be set")

	// connection_string unset
	err = ConfigValidate(&Configuration{DBTypeConfig: &DBTypeConfig{DatabaseType: SQLite}})
	require.EqualError(t, err, "datastore-sql: connection_string must be set")
}

func TestValidateMySQLConfigRequiresParseTime(t *testing.T) {
	cfg := &Configuration{
		ConnectionString: "user:pass@tcp(localhost:3306)/db",
		DBTypeConfig:     &DBTypeConfig{DatabaseType: MySQL},
	}
	err := ValidateMySQLConfig(cfg, false)
	require.ErrorContains(t, err, "missing parseTime=true param")
}
