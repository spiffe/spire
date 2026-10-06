package sqlcommon

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAzureConfigResolve(t *testing.T) {
	t.Run("auth_type", func(t *testing.T) {
		t.Run("unset is rejected", func(t *testing.T) {
			_, err := (&AzureConfig{}).Resolve()
			require.EqualError(t, err, `datastore-sql: auth_type must be set to one of "client_secret", "client_certificate", "workload_identity", "system_managed_identity", or "user_managed_identity"`)
		})

		t.Run("unknown value is rejected", func(t *testing.T) {
			_, err := (&AzureConfig{AuthType: "bogus"}).Resolve()
			require.EqualError(t, err, `datastore-sql: invalid auth_type "bogus": must be one of "client_secret", "client_certificate", "workload_identity", "system_managed_identity", or "user_managed_identity"`)
		})
	})

	t.Run("client_secret", func(t *testing.T) {
		base := func() *AzureConfig {
			return &AzureConfig{
				AuthType:     AzureAuthTypeClientSecret,
				TenantID:     "tenant-id",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			}
		}

		t.Run("succeeds with all fields set", func(t *testing.T) {
			resolved, err := base().Resolve()
			require.NoError(t, err)
			require.Equal(t, AzureAuthTypeClientSecret, resolved.AuthType)
			require.Equal(t, "tenant-id", resolved.TenantID)
			require.Equal(t, "client-id", resolved.ClientID)
			require.Equal(t, "client-secret", resolved.ClientSecret)
		})

		t.Run("missing tenant_id is rejected", func(t *testing.T) {
			cfg := base()
			cfg.TenantID = ""
			_, err := cfg.Resolve()
			require.EqualError(t, err, `datastore-sql: tenant_id must be set (or the AZURE_TENANT_ID environment variable) when auth_type is "client_secret"`)
		})

		t.Run("missing client_id is rejected", func(t *testing.T) {
			cfg := base()
			cfg.ClientID = ""
			_, err := cfg.Resolve()
			require.EqualError(t, err, `datastore-sql: client_id must be set (or the AZURE_CLIENT_ID environment variable) when auth_type is "client_secret"`)
		})

		t.Run("missing client_secret is rejected", func(t *testing.T) {
			cfg := base()
			cfg.ClientSecret = ""
			_, err := cfg.Resolve()
			require.EqualError(t, err, `datastore-sql: client_secret must be set (or the AZURE_CLIENT_SECRET environment variable) when auth_type is "client_secret"`)
		})

		t.Run("all fields fall back to environment variables", func(t *testing.T) {
			t.Setenv(envAzureTenantID, "env-tenant-id")
			t.Setenv(envAzureClientID, "env-client-id")
			t.Setenv(envAzureClientSecret, "env-client-secret")

			resolved, err := (&AzureConfig{AuthType: AzureAuthTypeClientSecret}).Resolve()
			require.NoError(t, err)
			require.Equal(t, "env-tenant-id", resolved.TenantID)
			require.Equal(t, "env-client-id", resolved.ClientID)
			require.Equal(t, "env-client-secret", resolved.ClientSecret)
		})

		t.Run("configuration takes precedence over environment variables", func(t *testing.T) {
			t.Setenv(envAzureTenantID, "env-tenant-id")
			t.Setenv(envAzureClientID, "env-client-id")
			t.Setenv(envAzureClientSecret, "env-client-secret")

			resolved, err := base().Resolve()
			require.NoError(t, err)
			require.Equal(t, "tenant-id", resolved.TenantID)
			require.Equal(t, "client-id", resolved.ClientID)
			require.Equal(t, "client-secret", resolved.ClientSecret)
		})
	})

	t.Run("client_certificate", func(t *testing.T) {
		base := func() *AzureConfig {
			return &AzureConfig{
				AuthType:              AzureAuthTypeClientCertificate,
				TenantID:              "tenant-id",
				ClientID:              "client-id",
				ClientCertificatePath: "cert-path",
			}
		}

		t.Run("succeeds with only the required fields set", func(t *testing.T) {
			resolved, err := base().Resolve()
			require.NoError(t, err)
			require.Equal(t, "cert-path", resolved.ClientCertificatePath)
			require.Empty(t, resolved.ClientCertificatePassword)
			require.False(t, resolved.SendCertificateChain)
		})

		t.Run("succeeds with the optional client_certificate_password set", func(t *testing.T) {
			cfg := base()
			cfg.ClientCertificatePassword = "cert-password"
			resolved, err := cfg.Resolve()
			require.NoError(t, err)
			require.Equal(t, "cert-password", resolved.ClientCertificatePassword)
		})

		t.Run("missing tenant_id is rejected", func(t *testing.T) {
			cfg := base()
			cfg.TenantID = ""
			_, err := cfg.Resolve()
			require.EqualError(t, err, `datastore-sql: tenant_id must be set (or the AZURE_TENANT_ID environment variable) when auth_type is "client_certificate"`)
		})

		t.Run("missing client_id is rejected", func(t *testing.T) {
			cfg := base()
			cfg.ClientID = ""
			_, err := cfg.Resolve()
			require.EqualError(t, err, `datastore-sql: client_id must be set (or the AZURE_CLIENT_ID environment variable) when auth_type is "client_certificate"`)
		})

		t.Run("missing client_certificate_path is rejected", func(t *testing.T) {
			cfg := base()
			cfg.ClientCertificatePath = ""
			_, err := cfg.Resolve()
			require.EqualError(t, err, `datastore-sql: client_certificate_path must be set (or the AZURE_CLIENT_CERTIFICATE_PATH environment variable) when auth_type is "client_certificate"`)
		})

		t.Run("client_certificate_path falls back to its environment variable", func(t *testing.T) {
			t.Setenv(envAzureClientCertificatePath, "env-cert-path")

			cfg := base()
			cfg.ClientCertificatePath = ""
			resolved, err := cfg.Resolve()
			require.NoError(t, err)
			require.Equal(t, "env-cert-path", resolved.ClientCertificatePath)
		})

		t.Run("client_certificate_password falls back to its environment variable", func(t *testing.T) {
			t.Setenv(envAzureClientCertificatePassword, "env-cert-password")

			resolved, err := base().Resolve()
			require.NoError(t, err)
			require.Equal(t, "env-cert-password", resolved.ClientCertificatePassword)
		})

		t.Run("configuration takes precedence over environment variables", func(t *testing.T) {
			t.Setenv(envAzureClientCertificatePath, "env-cert-path")
			t.Setenv(envAzureClientCertificatePassword, "env-cert-password")

			cfg := base()
			cfg.ClientCertificatePassword = "cfg-cert-password"
			resolved, err := cfg.Resolve()
			require.NoError(t, err)
			require.Equal(t, "cert-path", resolved.ClientCertificatePath)
			require.Equal(t, "cfg-cert-password", resolved.ClientCertificatePassword)
		})

		t.Run("send_certificate_chain", func(t *testing.T) {
			testCases := []struct {
				name     string
				cfgValue bool
				envValue string
				want     bool
			}{
				{name: "unset config and unset env is false", want: false},
				{name: "unset config and env \"true\" is true", envValue: "true", want: true},
				{name: "unset config and env \"1\" is true", envValue: "1", want: true},
				{name: "unset config and env \"TRUE\" is true (case-insensitive)", envValue: "TRUE", want: true},
				{name: "unset config and env \"yes\" is false (not a recognized value)", envValue: "yes", want: false},
				{name: "config true and unset env is true", cfgValue: true, want: true},
				{name: "config true and env \"false\" is still true", cfgValue: true, envValue: "false", want: true},
			}
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					if tc.envValue != "" {
						t.Setenv(envAzureSendCertificateChain, tc.envValue)
					}

					cfg := base()
					cfg.SendCertificateChain = tc.cfgValue
					resolved, err := cfg.Resolve()
					require.NoError(t, err)
					require.Equal(t, tc.want, resolved.SendCertificateChain)
				})
			}
		})
	})

	t.Run("workload_identity", func(t *testing.T) {
		base := func() *AzureConfig {
			return &AzureConfig{
				AuthType:           AzureAuthTypeWorkloadIdentity,
				TenantID:           "tenant-id",
				ClientID:           "client-id",
				FederatedTokenFile: "token-file",
			}
		}

		t.Run("succeeds with all fields set", func(t *testing.T) {
			resolved, err := base().Resolve()
			require.NoError(t, err)
			require.Equal(t, "token-file", resolved.FederatedTokenFile)
		})

		t.Run("missing tenant_id is rejected", func(t *testing.T) {
			cfg := base()
			cfg.TenantID = ""
			_, err := cfg.Resolve()
			require.EqualError(t, err, `datastore-sql: tenant_id must be set (or the AZURE_TENANT_ID environment variable) when auth_type is "workload_identity"`)
		})

		t.Run("missing client_id is rejected", func(t *testing.T) {
			cfg := base()
			cfg.ClientID = ""
			_, err := cfg.Resolve()
			require.EqualError(t, err, `datastore-sql: client_id must be set (or the AZURE_CLIENT_ID environment variable) when auth_type is "workload_identity"`)
		})

		t.Run("missing federated_token_file is rejected", func(t *testing.T) {
			cfg := base()
			cfg.FederatedTokenFile = ""
			_, err := cfg.Resolve()
			require.EqualError(t, err, `datastore-sql: federated_token_file must be set (or the AZURE_FEDERATED_TOKEN_FILE environment variable) when auth_type is "workload_identity"`)
		})

		t.Run("all fields fall back to environment variables", func(t *testing.T) {
			t.Setenv(envAzureTenantID, "env-tenant-id")
			t.Setenv(envAzureClientID, "env-client-id")
			t.Setenv(envAzureFederatedTokenFile, "env-token-file")

			resolved, err := (&AzureConfig{AuthType: AzureAuthTypeWorkloadIdentity}).Resolve()
			require.NoError(t, err)
			require.Equal(t, "env-tenant-id", resolved.TenantID)
			require.Equal(t, "env-client-id", resolved.ClientID)
			require.Equal(t, "env-token-file", resolved.FederatedTokenFile)
		})

		t.Run("configuration takes precedence over environment variables", func(t *testing.T) {
			t.Setenv(envAzureFederatedTokenFile, "env-token-file")

			resolved, err := base().Resolve()
			require.NoError(t, err)
			require.Equal(t, "token-file", resolved.FederatedTokenFile)
		})
	})

	t.Run("system_managed_identity", func(t *testing.T) {
		t.Run("succeeds with no other fields set", func(t *testing.T) {
			resolved, err := (&AzureConfig{AuthType: AzureAuthTypeSystemManagedIdentity}).Resolve()
			require.NoError(t, err)
			require.Equal(t, AzureAuthTypeSystemManagedIdentity, resolved.AuthType)
		})

		t.Run("succeeds even when unrelated fields are set", func(t *testing.T) {
			// client_id and managed_identity_resource_id only apply to a
			// user-assigned identity, so they must not be required (or even
			// consulted) here.
			resolved, err := (&AzureConfig{
				AuthType:                  AzureAuthTypeSystemManagedIdentity,
				ClientID:                  "client-id",
				ManagedIdentityResourceID: "resource-id",
			}).Resolve()
			require.NoError(t, err)
			require.NotNil(t, resolved)
		})
	})

	t.Run("user_managed_identity", func(t *testing.T) {
		t.Run("succeeds with only client_id set", func(t *testing.T) {
			resolved, err := (&AzureConfig{
				AuthType: AzureAuthTypeUserManagedIdentity,
				ClientID: "client-id",
			}).Resolve()
			require.NoError(t, err)
			require.Equal(t, "client-id", resolved.ClientID)
			require.Empty(t, resolved.ManagedIdentityResourceID)
		})

		t.Run("succeeds with only managed_identity_resource_id set", func(t *testing.T) {
			resolved, err := (&AzureConfig{
				AuthType:                  AzureAuthTypeUserManagedIdentity,
				ManagedIdentityResourceID: "resource-id",
			}).Resolve()
			require.NoError(t, err)
			require.Empty(t, resolved.ClientID)
			require.Equal(t, "resource-id", resolved.ManagedIdentityResourceID)
		})

		t.Run("succeeds with both client_id and managed_identity_resource_id set", func(t *testing.T) {
			resolved, err := (&AzureConfig{
				AuthType:                  AzureAuthTypeUserManagedIdentity,
				ClientID:                  "client-id",
				ManagedIdentityResourceID: "resource-id",
			}).Resolve()
			require.NoError(t, err)
			require.Equal(t, "client-id", resolved.ClientID)
			require.Equal(t, "resource-id", resolved.ManagedIdentityResourceID)
		})

		t.Run("client_id falls back to its environment variable", func(t *testing.T) {
			t.Setenv(envAzureClientID, "env-client-id")

			resolved, err := (&AzureConfig{AuthType: AzureAuthTypeUserManagedIdentity}).Resolve()
			require.NoError(t, err)
			require.Equal(t, "env-client-id", resolved.ClientID)
		})

		t.Run("missing both client_id and managed_identity_resource_id is rejected", func(t *testing.T) {
			_, err := (&AzureConfig{AuthType: AzureAuthTypeUserManagedIdentity}).Resolve()
			require.EqualError(t, err, `datastore-sql: client_id (or the AZURE_CLIENT_ID environment variable) or managed_identity_resource_id must be set when auth_type is "user_managed_identity"`)
		})
	})

	t.Run("Validate delegates to Resolve", func(t *testing.T) {
		require.NoError(t, (&AzureConfig{AuthType: AzureAuthTypeSystemManagedIdentity}).Validate())
		require.Error(t, (&AzureConfig{}).Validate())
	})
}
