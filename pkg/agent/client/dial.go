package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/spiffe"
	"github.com/spiffe/spire/pkg/common/idutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer/roundrobin"
	"google.golang.org/grpc/credentials"
)

const (
	_defaultDialTimeout = 30 * time.Second
)

type DialServerConfig struct {
	// Address is the SPIRE server address
	Address string

	// TrustDomain is the trust domain ID for the agent/server
	TrustDomain string

	// GetBundle is a required callback that returns the current trust bundle
	// for used to authenticate the server certificate.
	GetBundle func() []*x509.Certificate

	// GetAgentCertificate is an optional callback used to return the agent
	// certificate to present to the server during the TLS handshake.
	GetAgentCertificate func() *tls.Certificate

	// dialContext is an optional constructor for the grpc client connection.
	dialContext func(ctx context.Context, target string, opts ...grpc.DialOption) (*grpc.ClientConn, error)
}

func DialServer(ctx context.Context, config DialServerConfig) (*grpc.ClientConn, error) {
	tlsConfig := &tls.Config{
		// Disable standard verification. The VerifyPeerCertificate callback
		// will implement SPIFFE authentication.
		InsecureSkipVerify: true, //nolint: gosec

		// Perform SPIFFE authentication against the latest bundle for the
		// trust domain. The peer certificate must present the server SPIFFE
		// ID for the trust domain.
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			roots := x509.NewCertPool()
			for _, c := range config.GetBundle() {
				roots.AddCert(c)
			}
			trustDomainRoots := map[string]*x509.CertPool{
				idutil.TrustDomainID(config.TrustDomain): roots,
			}
			var serverChain []*x509.Certificate
			for _, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return err
				}
				serverChain = append(serverChain, cert)
			}

			_, err := spiffe.VerifyPeerCertificate(serverChain, trustDomainRoots, spiffe.ExpectPeer(idutil.ServerID(config.TrustDomain)))
			return err
		},
	}

	if config.GetAgentCertificate != nil {
		tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return config.GetAgentCertificate(), nil
		}
	}

	ctx, cancel := context.WithTimeout(ctx, _defaultDialTimeout)
	defer cancel()

	if config.dialContext == nil {
		config.dialContext = grpc.DialContext
	}
	client, err := config.dialContext(ctx, config.Address,
		grpc.WithBalancerName(roundrobin.Name), //nolint:staticcheck
		grpc.FailOnNonTempDialError(true),
		grpc.WithBlock(),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
	switch {
	case err == nil:
	case errors.Is(err, context.Canceled):
		return nil, fmt.Errorf("failed to dial %s: canceled", config.Address)
	case errors.Is(err, context.DeadlineExceeded):
		return nil, fmt.Errorf("failed to dial %s: timed out", config.Address)
	default:
		return nil, fmt.Errorf("failed to dial %s: %v", config.Address, err)
	}
	return client, nil
}
