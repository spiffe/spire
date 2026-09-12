package sqlcommon

import (
	"os"
	"strings"

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
	AWSMySQL      *AWSConfig   `hcl:"aws_mysql" json:"aws_mysql"`
	AWSPostgres   *AWSConfig   `hcl:"aws_postgres" json:"aws_postgres"`
	AzureMySQL    *AzureConfig `hcl:"azure_mysql" json:"azure_mysql"`
	AzurePostgres *AzureConfig `hcl:"azure_postgres" json:"azure_postgres"`
	DatabaseType  string
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

// Microsoft Entra ID (Azure AD) authentication mechanisms supported by the
// azure_postgres and azure_mysql database types.
const (
	AzureAuthTypeClientSecret          = "client_secret"
	AzureAuthTypeClientCertificate     = "client_certificate"
	AzureAuthTypeWorkloadIdentity      = "workload_identity"
	AzureAuthTypeSystemManagedIdentity = "system_managed_identity"
	AzureAuthTypeUserManagedIdentity   = "user_managed_identity"
)

// Environment variables read as fallbacks when the corresponding
// configuration option is not set, matching the conventions used by the
// Azure Identity SDK and the AKS workload identity webhook.
const (
	envAzureTenantID                  = "AZURE_TENANT_ID"
	envAzureClientID                  = "AZURE_CLIENT_ID"
	envAzureClientSecret              = "AZURE_CLIENT_SECRET" //nolint: gosec // false positive
	envAzureClientCertificatePath     = "AZURE_CLIENT_CERTIFICATE_PATH"
	envAzureClientCertificatePassword = "AZURE_CLIENT_CERTIFICATE_PASSWORD" //nolint: gosec // false positive
	envAzureSendCertificateChain      = "AZURE_CLIENT_SEND_CERTIFICATE_CHAIN"
	envAzureFederatedTokenFile        = "AZURE_FEDERATED_TOKEN_FILE"
)

// AzureConfig holds the settings needed to authenticate to an Azure database
// using a Microsoft Entra ID (Azure AD) access token instead of a password.
// AuthType selects which of the settings below are required; each one may be
// provided either directly in this configuration or through its
// corresponding environment variable.
type AzureConfig struct {
	// AuthType is one of "client_secret", "client_certificate",
	// "workload_identity", "system_managed_identity", or
	// "user_managed_identity".
	AuthType string `hcl:"auth_type" json:"auth_type"`

	// TenantID is required for auth_type "client_secret",
	// "client_certificate", and "workload_identity". Falls back to
	// AZURE_TENANT_ID.
	TenantID string `hcl:"tenant_id" json:"tenant_id"`

	// ClientID is required for auth_type "client_secret",
	// "client_certificate", and "workload_identity", and for
	// "user_managed_identity" when managed_identity_resource_id is not set.
	// Falls back to AZURE_CLIENT_ID.
	ClientID string `hcl:"client_id" json:"client_id"`

	// ClientSecret is required for auth_type "client_secret". Falls back to
	// AZURE_CLIENT_SECRET.
	ClientSecret string `hcl:"client_secret" json:"client_secret"`

	// ClientCertificatePath is required for auth_type "client_certificate".
	// It must point to a PEM or PKCS#12 file containing the client
	// certificate and private key. Falls back to
	// AZURE_CLIENT_CERTIFICATE_PATH.
	ClientCertificatePath string `hcl:"client_certificate_path" json:"client_certificate_path"`

	// ClientCertificatePassword decrypts ClientCertificatePath, if needed.
	// Falls back to AZURE_CLIENT_CERTIFICATE_PASSWORD.
	ClientCertificatePassword string `hcl:"client_certificate_password" json:"client_certificate_password"`

	// SendCertificateChain is optional and only applies to auth_type
	// "client_certificate". When true, the certificate chain from
	// ClientCertificatePath is sent with each token request, as required for
	// Subject Name/Issuer (SNI) authentication. Defaults to false. Falls back
	// to AZURE_CLIENT_SEND_CERTIFICATE_CHAIN ("1" or "true", case-insensitive)
	// when not set to true here.
	SendCertificateChain bool `hcl:"send_certificate_chain" json:"send_certificate_chain"`

	// FederatedTokenFile is required for auth_type "workload_identity". It is
	// the path to the Kubernetes service account token mounted by the AKS
	// workload identity webhook. Falls back to AZURE_FEDERATED_TOKEN_FILE.
	FederatedTokenFile string `hcl:"federated_token_file" json:"federated_token_file"`

	// ManagedIdentityResourceID is an alternative to ClientID for selecting
	// which user-assigned managed identity to use when auth_type is
	// "user_managed_identity".
	ManagedIdentityResourceID string `hcl:"managed_identity_resource_id" json:"managed_identity_resource_id"`
}

// ResolvedAzureAuth holds the concrete Microsoft Entra ID authentication
// settings to use, after resolving AzureConfig values against their
// corresponding environment variables.
type ResolvedAzureAuth struct {
	AuthType                  string
	TenantID                  string
	ClientID                  string
	ClientSecret              string
	ClientCertificatePath     string
	ClientCertificatePassword string
	SendCertificateChain      bool
	FederatedTokenFile        string
	ManagedIdentityResourceID string
}

func (a *AzureConfig) Validate() error {
	_, err := a.Resolve()
	return err
}

// Resolve validates AuthType and the settings it requires, resolving each
// against its corresponding environment variable when not set directly in
// the configuration. It returns an error naming the missing configuration
// option and environment variable when a required setting is absent.
func (a *AzureConfig) Resolve() (*ResolvedAzureAuth, error) {
	resolved := &ResolvedAzureAuth{
		AuthType:                  a.AuthType,
		TenantID:                  firstNonEmpty(a.TenantID, os.Getenv(envAzureTenantID)),
		ClientID:                  firstNonEmpty(a.ClientID, os.Getenv(envAzureClientID)),
		ClientSecret:              firstNonEmpty(a.ClientSecret, os.Getenv(envAzureClientSecret)),
		ClientCertificatePath:     firstNonEmpty(a.ClientCertificatePath, os.Getenv(envAzureClientCertificatePath)),
		ClientCertificatePassword: firstNonEmpty(a.ClientCertificatePassword, os.Getenv(envAzureClientCertificatePassword)),
		SendCertificateChain:      a.SendCertificateChain || parseBoolEnv(os.Getenv(envAzureSendCertificateChain)),
		FederatedTokenFile:        firstNonEmpty(a.FederatedTokenFile, os.Getenv(envAzureFederatedTokenFile)),
		ManagedIdentityResourceID: a.ManagedIdentityResourceID,
	}

	switch a.AuthType {
	case AzureAuthTypeClientSecret:
		if resolved.TenantID == "" {
			return nil, missingAzureSettingError("tenant_id", envAzureTenantID, a.AuthType)
		}
		if resolved.ClientID == "" {
			return nil, missingAzureSettingError("client_id", envAzureClientID, a.AuthType)
		}
		if resolved.ClientSecret == "" {
			return nil, missingAzureSettingError("client_secret", envAzureClientSecret, a.AuthType)
		}
	case AzureAuthTypeClientCertificate:
		if resolved.TenantID == "" {
			return nil, missingAzureSettingError("tenant_id", envAzureTenantID, a.AuthType)
		}
		if resolved.ClientID == "" {
			return nil, missingAzureSettingError("client_id", envAzureClientID, a.AuthType)
		}
		if resolved.ClientCertificatePath == "" {
			return nil, missingAzureSettingError("client_certificate_path", envAzureClientCertificatePath, a.AuthType)
		}
	case AzureAuthTypeWorkloadIdentity:
		if resolved.TenantID == "" {
			return nil, missingAzureSettingError("tenant_id", envAzureTenantID, a.AuthType)
		}
		if resolved.ClientID == "" {
			return nil, missingAzureSettingError("client_id", envAzureClientID, a.AuthType)
		}
		if resolved.FederatedTokenFile == "" {
			return nil, missingAzureSettingError("federated_token_file", envAzureFederatedTokenFile, a.AuthType)
		}
	case AzureAuthTypeSystemManagedIdentity:
		// No further settings are required; the identity assigned to the
		// hosting environment (e.g. the VM or AKS pod) is used.
	case AzureAuthTypeUserManagedIdentity:
		if resolved.ClientID == "" && resolved.ManagedIdentityResourceID == "" {
			return nil, NewSQLError("client_id (or the %s environment variable) or managed_identity_resource_id must be set when auth_type is %q",
				envAzureClientID, AzureAuthTypeUserManagedIdentity)
		}
	case "":
		return nil, NewSQLError("auth_type must be set to one of %q, %q, %q, %q, or %q",
			AzureAuthTypeClientSecret, AzureAuthTypeClientCertificate, AzureAuthTypeWorkloadIdentity, AzureAuthTypeSystemManagedIdentity, AzureAuthTypeUserManagedIdentity)
	default:
		return nil, NewSQLError("invalid auth_type %q: must be one of %q, %q, %q, %q, or %q",
			a.AuthType, AzureAuthTypeClientSecret, AzureAuthTypeClientCertificate, AzureAuthTypeWorkloadIdentity, AzureAuthTypeSystemManagedIdentity, AzureAuthTypeUserManagedIdentity)
	}

	return resolved, nil
}

func missingAzureSettingError(field, envVar, authType string) error {
	return NewSQLError("%s must be set (or the %s environment variable) when auth_type is %q", field, envVar, authType)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// parseBoolEnv matches the Azure Identity SDK's own parsing of
// AZURE_CLIENT_SEND_CERTIFICATE_CHAIN: "1" or "true" (case-insensitive).
func parseBoolEnv(v string) bool {
	return v == "1" || strings.EqualFold(v, "true")
}

// GetConnectionString returns the connection string corresponding to the database connection.
func GetConnectionString(cfg *Configuration, isReadOnly bool) string {
	connectionString := cfg.ConnectionString
	if isReadOnly {
		connectionString = cfg.RoConnectionString
	}
	return connectionString
}
