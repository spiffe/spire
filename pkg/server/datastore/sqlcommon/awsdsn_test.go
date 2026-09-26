package sqlcommon

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildAWSPostgresDSNNoPassword(t *testing.T) {
	isolatePostgresEnv(t)

	dsn, err := BuildAWSPostgresDSN(awsPostgresConfig(
		"postgres://dbuser@my-instance.rds.amazonaws.com:5432/spire"), false)
	require.NoError(t, err)
	require.Contains(t, dsn, "my-instance.rds.amazonaws.com:5432")
}

func TestBuildAWSPostgresDSNUsesReadOnlyConnectionString(t *testing.T) {
	isolatePostgresEnv(t)

	cfg := awsPostgresConfig("postgres://dbuser@rw-host:5432/spire")
	cfg.RoConnectionString = "postgres://dbuser@ro-host:5432/spire"

	dsn, err := BuildAWSPostgresDSN(cfg, true)
	require.NoError(t, err)
	require.Contains(t, dsn, "ro-host:5432")
	require.NotContains(t, dsn, "rw-host")
}

func TestBuildAWSPostgresDSNRejectsPassword(t *testing.T) {
	isolatePostgresEnv(t)

	for _, connString := range []string{
		"postgres://dbuser:secret@host:5432/spire",
		"postgres://dbuser@host:5432/spire?password=secret",
		"host=host port=5432 user=dbuser password=secret dbname=spire",
		"host=host port=5432 user=dbuser password = secret dbname=spire",
	} {
		_, err := BuildAWSPostgresDSN(awsPostgresConfig(connString), false)
		require.ErrorContains(t, err, "password should not be set when using IAM authentication",
			"connString=%q", connString)
	}
}

func TestBuildAWSPostgresDSNAllowsEmptyPassword(t *testing.T) {
	isolatePostgresEnv(t)

	_, err := BuildAWSPostgresDSN(awsPostgresConfig(
		"postgres://dbuser:@my-instance.rds.amazonaws.com:5432/spire"), false)
	require.NoError(t, err)
}

func awsPostgresConfig(connString string) *Configuration {
	return &Configuration{
		ConnectionString: connString,
		DBTypeConfig: &DBTypeConfig{
			DatabaseType: AWSPostgreSQL,
			AWSPostgres:  &AWSConfig{Region: "us-west-2", AccessKeyID: "AKID", SecretAccessKey: "SECRET"},
		},
	}
}

// isolatePostgresEnv keeps the developer's libpq environment out of the test:
// pgx.ParseConfig falls back to PGPASSWORD and the passfile for a password.
func isolatePostgresEnv(t *testing.T) {
	t.Setenv("PGPASSWORD", "")
	t.Setenv("PGPASSFILE", filepath.Join(t.TempDir(), "nonexistent"))
}
