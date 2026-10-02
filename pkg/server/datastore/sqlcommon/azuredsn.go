package sqlcommon

import (
	"errors"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/spiffe/spire/pkg/server/datastore/sqldriver/azurerds"
)

// BuildAzurePostgresDSN builds the Microsoft Entra ID DSN for an Azure
// PostgreSQL connection. It rejects a connection string carrying a password,
// since Entra ID auth supplies a rotating access token instead.
func BuildAzurePostgresDSN(cfg *Configuration, isReadOnly bool) (string, error) {
	connString := GetConnectionString(cfg, isReadOnly)
	c, err := pgx.ParseConfig(connString)
	if err != nil {
		return "", err
	}
	if c.Password != "" {
		return "", errors.New("invalid postgres configuration: password should not be set when using Microsoft Entra ID authentication")
	}

	return buildAzureDSN(cfg.DBTypeConfig.AzurePostgres, azurerds.PostgresDriverName, connString)
}

// BuildAzureMySQLDSN builds the Microsoft Entra ID DSN for an Azure MySQL
// connection. It rejects a connection string carrying a password, since
// Entra ID auth supplies a rotating access token instead.
func BuildAzureMySQLDSN(cfg *Configuration, mysqlConfig *mysql.Config) (string, error) {
	if mysqlConfig.Passwd != "" {
		return "", errors.New("invalid mysql configuration: password should not be set when using Microsoft Entra ID authentication")
	}

	return buildAzureDSN(cfg.DBTypeConfig.AzureMySQL, azurerds.MySQLDriverName, mysqlConfig.FormatDSN())
}

func buildAzureDSN(azureConfig *AzureConfig, driverName, connString string) (string, error) {
	resolved, err := azureConfig.Resolve()
	if err != nil {
		return "", err
	}

	azurerdsConfig := &azurerds.Config{
		AuthType:                  resolved.AuthType,
		TenantID:                  resolved.TenantID,
		ClientID:                  resolved.ClientID,
		ClientSecret:              resolved.ClientSecret,
		ClientCertificatePath:     resolved.ClientCertificatePath,
		ClientCertificatePassword: resolved.ClientCertificatePassword,
		SendCertificateChain:      resolved.SendCertificateChain,
		FederatedTokenFile:        resolved.FederatedTokenFile,
		ManagedIdentityResourceID: resolved.ManagedIdentityResourceID,
		DriverName:                driverName,
		ConnString:                connString,
	}
	return azurerdsConfig.FormatDSN()
}
