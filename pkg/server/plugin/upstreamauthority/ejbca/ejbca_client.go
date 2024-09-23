package ejbca

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	ejbcaclient "github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	"github.com/gogo/status"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"google.golang.org/grpc/codes"
)

type ejbcaClient interface {
	EnrollPkcs10Certificate(ctx context.Context) ejbcaclient.ApiEnrollPkcs10CertificateRequest
}

func (p *Plugin) getAuthenticator(config *Config) (ejbcaclient.Authenticator, error) {
	var err error
	logger := p.logger.Named("getAuthenticator")

	var caChain []*x509.Certificate
	if config.CaCertPath != "" {
		logger.Debug("Parsing CA chain from file", "path", config.CaCertPath)
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

	logger.Debug("Creating mTLS authenticator")

	logger.Debug("Reading client certificate from file", "path", config.ClientCertPath)
	clientCertBytes, err := p.hooks.readFile(config.ClientCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read client certificate from file: %w", err)
	}
	logger.Debug("Reading client key from file", "path", config.ClientCertKeyPath)
	clientKeyBytes, err := p.hooks.readFile(config.ClientCertKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read client key from file: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(clientCertBytes, clientKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	authenticator, err := ejbcaclient.NewMTLSAuthenticatorBuilder().
		WithClientCertificate(&tlsCert).
		WithCaCertificates(caChain).
		Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build MTLS authenticator: %w", err)
	}

	logger.Debug("Created mTLS authenticator")

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
