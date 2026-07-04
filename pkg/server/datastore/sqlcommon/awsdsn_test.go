package sqlcommon

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildAWSPostgresDSNNoPassword(t *testing.T) {
	// Isolate from any PGPASSWORD the CI runner may have set: pgx.ParseConfig
	// merges libpq env fallbacks, so the connection string alone would not be
	// authoritative otherwise. Mirrors awsrds_test.go's handling.
	t.Setenv("PGPASSWORD", "")

	dsn, err := BuildAWSPostgresDSN(awsPostgresConfig(
		"postgres://dbuser@my-instance.rds.amazonaws.com:5432/spire"))
	require.NoError(t, err)
	require.Contains(t, dsn, "my-instance.rds.amazonaws.com:5432")
}

func TestBuildAWSPostgresDSNRejectsPassword(t *testing.T) {
	t.Setenv("PGPASSWORD", "")

	for _, connString := range []string{
		"postgres://dbuser:secret@host:5432/spire",
		"postgres://dbuser@host:5432/spire?password=secret",
		"host=host port=5432 user=dbuser password=secret dbname=spire",
		"host=host port=5432 user=dbuser password = secret dbname=spire",
	} {
		_, err := BuildAWSPostgresDSN(awsPostgresConfig(connString))
		require.ErrorContains(t, err, "password should not be set when using IAM authentication",
			"connString=%q", connString)
	}
}

func TestBuildAWSPostgresDSNAllowsEmptyPassword(t *testing.T) {
	t.Setenv("PGPASSWORD", "")

	_, err := BuildAWSPostgresDSN(awsPostgresConfig(
		"postgres://dbuser:@my-instance.rds.amazonaws.com:5432/spire"))
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
