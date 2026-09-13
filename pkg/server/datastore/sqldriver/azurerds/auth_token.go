package azurerds

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

const (
	// clockSkew makes sure that the authentication token is valid for one
	// more minute.
	clockSkew = time.Minute

	// ossRDBMSScope is the OAuth2 scope used to request a Microsoft Entra ID
	// access token that both Azure Database for PostgreSQL and Azure
	// Database for MySQL accept as a password.
	ossRDBMSScope = "https://ossrdbms-aad.database.windows.net/.default"
)

// nowFunc returns the current time and can be overridden in tests.
var nowFunc = time.Now

type authTokenBuilder interface {
	buildAuthToken(ctx context.Context, config *Config) (azcore.AccessToken, error)
}

// authToken is shared by every connection opened for a given DSN (see
// sqlDriverWrapper.tokensMap), so getAuthToken can be called concurrently by
// multiple goroutines as database/sql grows the connection pool. mu
// serializes access to the cached token, which also has the effect of
// coalescing concurrent refreshes into a single token request.
type authToken struct {
	mu          sync.Mutex
	cachedToken string
	expiresAt   time.Time
}

func (a *authToken) getAuthToken(ctx context.Context, config *Config, tokenBuilder authTokenBuilder) (string, error) {
	if config == nil {
		return "", errors.New("missing config")
	}

	if tokenBuilder == nil {
		return "", errors.New("missing token builder")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.shouldRotate() {
		return a.cachedToken, nil
	}

	accessToken, err := tokenBuilder.buildAuthToken(ctx, config)
	if err != nil {
		return "", fmt.Errorf("failed to build authentication token: %w", err)
	}

	a.cachedToken = accessToken.Token
	a.expiresAt = accessToken.ExpiresOn
	return a.cachedToken, nil
}

// shouldRotate returns true if the cached token is either expired or is
// expiring soon. This means that this function will return true also if the
// token is still valid but should be rotated because it's expiring soon. The
// time window that establish when a cached token should be rotated even if it's
// still valid is adjusted by a clock skew, defined in the clockSkew constant.
func (a *authToken) shouldRotate() bool {
	return nowFunc().Add(clockSkew).Sub(a.expiresAt) >= 0
}

type azureTokenBuilder struct{}

func (a *azureTokenBuilder) buildAuthToken(ctx context.Context, config *Config) (azcore.AccessToken, error) {
	cred, err := newAzureCredential(config)
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to create Azure credential: %w", err)
	}

	return cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{ossRDBMSScope},
	})
}

// newAzureCredential returns a credential used to obtain Microsoft Entra ID
// access tokens, built according to config.AuthType. config is expected to
// already be fully resolved (e.g. via sqlcommon.AzureConfig.Resolve), so
// every field required by AuthType is populated.
func newAzureCredential(config *Config) (azcore.TokenCredential, error) {
	switch config.AuthType {
	case AuthTypeClientSecret:
		return azidentity.NewClientSecretCredential(config.TenantID, config.ClientID, config.ClientSecret, nil)
	case AuthTypeClientCertificate:
		return newClientCertificateCredential(config)
	case AuthTypeWorkloadIdentity:
		return azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{
			TenantID:      config.TenantID,
			ClientID:      config.ClientID,
			TokenFilePath: config.FederatedTokenFile,
		})
	case AuthTypeSystemManagedIdentity:
		return azidentity.NewManagedIdentityCredential(nil)
	case AuthTypeUserManagedIdentity:
		return newUserManagedIdentityCredential(config)
	default:
		return nil, fmt.Errorf("unsupported auth_type %q", config.AuthType)
	}
}

func newClientCertificateCredential(config *Config) (azcore.TokenCredential, error) {
	certData, err := os.ReadFile(config.ClientCertificatePath)
	if err != nil {
		return nil, fmt.Errorf("could not read client_certificate_path: %w", err)
	}

	var password []byte
	if config.ClientCertificatePassword != "" {
		password = []byte(config.ClientCertificatePassword)
	}

	certs, key, err := azidentity.ParseCertificates(certData, password)
	if err != nil {
		return nil, fmt.Errorf("could not parse client certificate: %w", err)
	}

	return azidentity.NewClientCertificateCredential(config.TenantID, config.ClientID, certs, key, &azidentity.ClientCertificateCredentialOptions{
		SendCertificateChain: config.SendCertificateChain,
	})
}

func newUserManagedIdentityCredential(config *Config) (azcore.TokenCredential, error) {
	opts := &azidentity.ManagedIdentityCredentialOptions{}

	switch {
	case config.ManagedIdentityResourceID != "":
		opts.ID = azidentity.ResourceID(config.ManagedIdentityResourceID)
	case config.ClientID != "":
		opts.ID = azidentity.ClientID(config.ClientID)
	default:
		return nil, errors.New("managed_identity_resource_id or client_id must be set for auth_type \"user_managed_identity\"")
	}

	return azidentity.NewManagedIdentityCredential(opts)
}
