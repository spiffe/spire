package sqlcommon

import (
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
)

func TestBuildAzurePostgresDSN(t *testing.T) {
	isolatePostgresEnv(t)

	cfg := azurePostgresConfig("postgres://dbuser@rw-host:5432/spire")
	cfg.RoConnectionString = "postgres://dbuser@ro-host:5432/spire"

	dsn, err := BuildAzurePostgresDSN(cfg, false)
	require.NoError(t, err)
	require.Contains(t, dsn, "rw-host")
	require.Contains(t, dsn, `"auth_type":"system_managed_identity"`)

	dsn, err = BuildAzurePostgresDSN(cfg, true)
	require.NoError(t, err)
	require.Contains(t, dsn, "ro-host")
}

func TestBuildAzurePostgresDSNRejectsPassword(t *testing.T) {
	isolatePostgresEnv(t)

	_, err := BuildAzurePostgresDSN(azurePostgresConfig("postgres://dbuser:secret@host:5432/spire"), false)
	require.ErrorContains(t, err, "password should not be set when using Microsoft Entra ID authentication")
}

func TestBuildAzurePostgresDSNResolveError(t *testing.T) {
	isolatePostgresEnv(t)

	cfg := azurePostgresConfig("postgres://dbuser@host:5432/spire")
	cfg.DBTypeConfig.AzurePostgres.AuthType = "unknown"
	_, err := BuildAzurePostgresDSN(cfg, false)
	require.Error(t, err)
}

func TestBuildAzureMySQLDSN(t *testing.T) {
	cfg := &Configuration{
		DBTypeConfig: &DBTypeConfig{
			DatabaseType: AzureMySQL,
			AzureMySQL:   &AzureConfig{AuthType: AzureAuthTypeSystemManagedIdentity},
		},
	}

	dsn, err := BuildAzureMySQLDSN(cfg, &mysql.Config{User: "dbuser", Net: "tcp", Addr: "host:3306", DBName: "spire"})
	require.NoError(t, err)
	require.Contains(t, dsn, "host:3306")

	_, err = BuildAzureMySQLDSN(cfg, &mysql.Config{User: "dbuser", Passwd: "secret", Net: "tcp", Addr: "host:3306"})
	require.ErrorContains(t, err, "password should not be set when using Microsoft Entra ID authentication")
}

func azurePostgresConfig(connString string) *Configuration {
	return &Configuration{
		ConnectionString: connString,
		DBTypeConfig: &DBTypeConfig{
			DatabaseType:  AzurePostgreSQL,
			AzurePostgres: &AzureConfig{AuthType: AzureAuthTypeSystemManagedIdentity},
		},
	}
}
