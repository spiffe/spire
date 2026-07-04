package sqlcommon

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildConfigSQLite(t *testing.T) {
	cfg, err := BuildConfig(`
		database_type = "sqlite3"
		connection_string = "file:test.db"
	`)
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
	`)
	require.NoError(t, err)
	require.Equal(t, AWSPostgreSQL, cfg.DBTypeConfig.DatabaseType)
	require.NotNil(t, cfg.DBTypeConfig.AWSPostgres)
	require.Equal(t, "us-west-2", cfg.DBTypeConfig.AWSPostgres.Region)
	require.NoError(t, ConfigValidate(cfg))
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
