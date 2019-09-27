package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/spiffe"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/zeebo/errs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer/roundrobin"
	"google.golang.org/grpc/credentials"
)

type DialServerConfig struct {
	// Log is the logger for dialing related events
	Log logrus.FieldLogger

	// Address is the SPIRE server address
	Address string

	// TrustDomain is the trust domain ID for the agent/server
	TrustDomain string

	// GetBundle is a callback that returns the current trust bundle
	// for used to authenticate the server certificate. It is required unless
	// InsecureBootstrap is true.
	GetBundle func() []*x509.Certificate

	// GetAgentCertificate is an optional callback used to return the agent
	// certificate to present to the server during the TLS handshake.
	GetAgentCertificate func() *tls.Certificate

	// InsecureBootstrap indicates that the server certificate should be
	// trusted.
	InsecureBootstrap bool
}

func DialServer(ctx context.Context, config DialServerConfig) (*grpc.ClientConn, error) {
	if config.GetBundle == nil && !config.InsecureBootstrap {
		return nil, errs.New("GetBundle is required unless InsecureBootstrap is true")
	}
	tlsConfig := &tls.Config{
		// Disable standard verification. The VerifyPeerCertificate callback
		// will implement SPIFFE authentication.
		InsecureSkipVerify: true,

		// Perform SPIFFE authentication against the latest bundle for the
		// trust domain. The peer certificate must present the server SPIFFE
		// ID for the trust domain.
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			var serverChain []*x509.Certificate
			for _, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return errs.Wrap(err)
				}
				serverChain = append(serverChain, cert)
			}

			if len(serverChain) == 0 {
				// This is not really possible without a catastrophic bug
				// creeping into the TLS stack.
				return errs.New("server chain is unexpectedly empty")
			}

			expectedServerID := idutil.ServerID(config.TrustDomain)

			if config.GetBundle == nil {
				config.Log.Warn("Insecure bootstrap enabled; skipping server certificate verification")
				// Insecure bootstrapping. Do not verify the server chain but
				// rather do a simple soft verification that the server URI
				// matches the expected SPIFFE ID. This is not a security
				// feature but rather a check that we've reached what
				// appears to be the right trust domain server.
				if len(serverChain[0].URIs) != 1 || serverChain[0].URIs[0].String() != expectedServerID {
					return errs.New("expected server SPIFFE ID %q; got %q", expectedServerID, serverChain[0].URIs)
				}
				return nil
			}

			// Secure bootstrapping. The server must chain back to the
			// trust bundle and present the expected SPIFFE ID.
			roots := x509.NewCertPool()
			for _, c := range config.GetBundle() {
				roots.AddCert(c)
			}
			trustDomainRoots := map[string]*x509.CertPool{
				idutil.TrustDomainID(config.TrustDomain): roots,
			}
			_, err := spiffe.VerifyPeerCertificate(serverChain, trustDomainRoots, spiffe.ExpectPeer(expectedServerID))
			return err
		},
	}

	if config.GetAgentCertificate != nil {
		tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return config.GetAgentCertificate(), nil
		}
	}

	return grpc.DialContext(ctx, config.Address,
		grpc.WithBalancerName(roundrobin.Name),
		grpc.FailOnNonTempDialError(true),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
}
