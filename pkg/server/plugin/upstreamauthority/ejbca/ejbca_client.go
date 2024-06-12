package ejbca

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

	ejbcaclient "github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	"github.com/gogo/status"
	"github.com/hashicorp/hcl"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"google.golang.org/grpc/codes"
)

type ejbcaClient interface {
	EnrollPkcs10Certificate(ctx context.Context) ejbcaclient.ApiEnrollPkcs10CertificateRequest
}

func (p *Plugin) parseConfig(req *configv1.ConfigureRequest) (*Config, error) {
	logger := p.logger.Named("parseConfig")
	config := new(Config)
	logger.Trace("Decoding EJBCA configuration")
	if err := hcl.Decode(&config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}

	switch {
	case config.OAuth != nil:
		logger.Debug("Found OAuth configuration section in config")
		if config.OAuth.TokenURL == "" {
			config.OAuth.TokenURL = p.hooks.getEnv("EJBCA_OAUTH_TOKEN_URL")
		}
		if config.OAuth.ClientID == "" {
			config.OAuth.ClientID = p.hooks.getEnv("EJBCA_OAUTH_CLIENT_ID")
		}
		if config.OAuth.ClientSecret == "" {
			config.OAuth.ClientSecret = p.hooks.getEnv("EJBCA_OAUTH_CLIENT_SECRET")
		}
		if config.OAuth.Scopes == "" {
			config.OAuth.Scopes = p.hooks.getEnv("EJBCA_OAUTH_SCOPES")
		}
		if config.OAuth.Audience == "" {
			config.OAuth.Audience = p.hooks.getEnv("EJBCA_OAUTH_AUDIENCE")
		}

		if config.OAuth.TokenURL == "" {
			logger.Error("Token URL is required for OAuth authentication")
			return nil, status.Error(codes.InvalidArgument, "token_url or EJBCA_OAUTH_TOKEN_URL is required for OAuth authentication")
		}
		if config.OAuth.ClientID == "" {
			logger.Error("Client ID is required for OAuth authentication")
			return nil, status.Error(codes.InvalidArgument, "client_id or EJBCA_OAUTH_CLIENT_ID is required for OAuth authentication")
		}
		if config.OAuth.ClientSecret == "" {
			logger.Error("Client secret is required for OAuth authentication")
			return nil, status.Error(codes.InvalidArgument, "client_secret or EJBCA_OAUTH_CLIENT_SECRET is required for OAuth authentication")
		}
	case config.CertAuth != nil:
		if config.CertAuth.ClientCertPath == "" {
			config.CertAuth.ClientCertPath = p.hooks.getEnv("EJBCA_CLIENT_CERT_PATH")
		}
		if config.CertAuth.ClientKeyPath == "" {
			config.CertAuth.ClientKeyPath = p.hooks.getEnv("EJBCA_CLIENT_CERT_KEY_PATH")
		}

		if config.CertAuth.ClientCertPath == "" {
			logger.Error("Client certificate is required for mTLS authentication")
			return nil, status.Error(codes.InvalidArgument, "client_cert or EJBCA_CLIENT_CERT_PATH is required for mTLS authentication")
		}
		if config.CertAuth.ClientKeyPath == "" {
			logger.Error("Client key is required for mTLS authentication")
			return nil, status.Error(codes.InvalidArgument, "client_key or EJBCA_CLIENT_KEY_PATH is required for mTLS authentication")
		}
	default:
		logger.Error("No authentication method specified")
		return nil, status.Error(codes.InvalidArgument, "no authentication method specified")
	}

	if config.CaCertPath == "" {
		config.CaCertPath = p.hooks.getEnv("EJBCA_CA_CERT_PATH")
	}

	if config.Hostname == "" {
		return nil, status.Error(codes.InvalidArgument, "hostname is required")
	}
	if config.CAName == "" {
		return nil, status.Error(codes.InvalidArgument, "ca_name is required")
	}
	if config.EndEntityProfileName == "" {
		return nil, status.Error(codes.InvalidArgument, "end_entity_profile_name is required")
	}
	if config.CertificateProfileName == "" {
		return nil, status.Error(codes.InvalidArgument, "certificate_profile_name is required")
	}

	return config, nil
}

func (p *Plugin) getAuthenticator(config *Config) (ejbcaclient.Authenticator, error) {
	var err error
	logger := p.logger.Named("getAuthenticator")

	var caChain []*x509.Certificate
	if config.CaCertPath != "" {
		logger.Trace("Parsing CA chain from file", "path", config.CaCertPath)
		caChainBytes, err := p.hooks.readFile(config.CaCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA chain from file: %w", err)
		}

		chain, err := pemutil.ParseCertificates(caChainBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA chain: %w", err)
		}

		logger.Debug("Parsed CA chain", "length", len(caChain))
		caChain = chain
	}

	var authenticator ejbcaclient.Authenticator
	switch {
	case config.OAuth != nil:
		logger.Trace("Creating OAuth authenticator")
		scopes := strings.Split(config.OAuth.Scopes, " ")

		authenticator, err = ejbcaclient.NewOAuthAuthenticatorBuilder().
			WithCaCertificates(caChain).
			WithTokenUrl(config.OAuth.TokenURL).
			WithClientId(config.OAuth.ClientID).
			WithClientSecret(config.OAuth.ClientSecret).
			WithAudience(config.OAuth.Audience).
			WithScopes(scopes).
			Build()
		if err != nil {
			logger.Error("Failed to build OAuth authenticator", "error", err)
			return nil, fmt.Errorf("failed to build OAuth authenticator: %w", err)
		}

		logger.Debug("Created OAuth authenticator")
	case config.CertAuth != nil:
		logger.Trace("Creating mTLS authenticator")

		logger.Debug("Reading client certificate from file", "path", config.CertAuth.ClientCertPath)
		clientCertBytes, err := p.hooks.readFile(config.CertAuth.ClientCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read client certificate from file: %w", err)
		}
		logger.Debug("Reading client key from file", "path", config.CertAuth.ClientKeyPath)
		clientKeyBytes, err := p.hooks.readFile(config.CertAuth.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read client key from file: %w", err)
		}

		tlsCert, err := tls.X509KeyPair(clientCertBytes, clientKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}

		authenticator, err = ejbcaclient.NewMTLSAuthenticatorBuilder().
			WithClientCertificate(&tlsCert).
			WithCaCertificates(caChain).
			Build()
		if err != nil {
			return nil, fmt.Errorf("failed to build MTLS authenticator: %w", err)
		}

		logger.Debug("Created mTLS authenticator")
	default:
		logger.Error("No authentication method specified")
		return nil, status.Error(codes.InvalidArgument, "no authentication method specified")
	}

	return authenticator, nil
}

// newEjbcaClient generates a new EJBCA client based on the provided configuration.
func (p *Plugin) newEjbcaClient(config *Config, authenticator ejbcaclient.Authenticator) (ejbcaClient, error) {
	logger := p.logger.Named("newEjbcaClient")
	if config == nil {
		return nil, status.Error(codes.InvalidArgument, "config is required")
	}
	if authenticator == nil {
		return nil, status.Error(codes.InvalidArgument, "authenticator is required")
	}

	configuration := ejbcaclient.NewConfiguration()
	configuration.Host = config.Hostname

	configuration.SetAuthenticator(authenticator)

	ejbcaClient, err := ejbcaclient.NewAPIClient(configuration)
	if err != nil {
		return nil, err
	}

	logger.Info("Created EJBCA REST API client for EJBCA UpstreamAuthority plugin")
	return ejbcaClient.V1CertificateApi, nil
}
