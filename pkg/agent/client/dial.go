package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"

	"github.com/spiffe/go-spiffe/spiffe"
	"github.com/spiffe/spire/pkg/common/idutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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
}

func DialServer(ctx context.Context, config DialServerConfig) (*grpc.ClientConn, error) {
	tlsConfig := &tls.Config{
		// Disable standard verification. The VerifyPeerCertificate callback
		// will implement SPIFFE authentication.
		InsecureSkipVerify: true,

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

	return grpc.DialContext(ctx, config.Address,
		grpc.FailOnNonTempDialError(true),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
}
