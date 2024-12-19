package client

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/tlspolicy"
	"github.com/spiffe/spire/pkg/common/x509util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	defaultDialTimeout      = 30 * time.Second
	roundRobinServiceConfig = `{ "loadBalancingConfig": [ { "round_robin": {} } ] }`
)

type ServerClientConfig struct {
	// Address is the SPIRE server address
	Address string

	TrustDomain spiffeid.TrustDomain

	// GetBundle is a required callback that returns the current trust bundle
	// for used to authenticate the server certificate.
	GetBundle func() []*x509.Certificate

	// GetAgentCertificate is an optional callback used to return the agent
	// certificate to present to the server during the TLS handshake.
	GetAgentCertificate func() *tls.Certificate

	// TLSPolicy determines the post-quantum-safe policy to apply to all TLS connections.
	TLSPolicy tlspolicy.Policy

	// dialOpts are optional gRPC dial options
	dialOpts []grpc.DialOption
}

func NewServerGRPCClient(config ServerClientConfig) (*grpc.ClientConn, error) {
	bundleSource := newBundleSource(config.TrustDomain, config.GetBundle)
	serverID, err := idutil.ServerID(config.TrustDomain)
	if err != nil {
		return nil, err
	}
	authorizer := tlsconfig.AuthorizeID(serverID)

	var tlsConfig *tls.Config
	if config.GetAgentCertificate == nil {
		tlsConfig = tlsconfig.TLSClientConfig(bundleSource, authorizer)
	} else {
		tlsConfig = tlsconfig.MTLSClientConfig(newX509SVIDSource(config.GetAgentCertificate), bundleSource, authorizer)
	}

	err = tlspolicy.ApplyPolicy(tlsConfig, config.TLSPolicy)
	if err != nil {
		return nil, err
	}

	dialOpts := config.dialOpts
	if dialOpts == nil {
		dialOpts = []grpc.DialOption{
			grpc.WithDefaultServiceConfig(roundRobinServiceConfig),
			grpc.WithDisableServiceConfig(),
			grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		}
	}

	client, err := grpc.NewClient(config.Address, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	return client, nil
}

type bundleSource struct {
	td     spiffeid.TrustDomain
	getter func() []*x509.Certificate
}

func newBundleSource(td spiffeid.TrustDomain, getter func() []*x509.Certificate) x509bundle.Source {
	return &bundleSource{td: td, getter: getter}
}

func (s *bundleSource) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	bundle := x509bundle.FromX509Authorities(s.td, s.getter())
	return bundle.GetX509BundleForTrustDomain(trustDomain)
}

type x509SVIDSource struct {
	getter func() *tls.Certificate
}

func newX509SVIDSource(getter func() *tls.Certificate) x509svid.Source {
	return &x509SVIDSource{getter: getter}
}

func (s *x509SVIDSource) GetX509SVID() (*x509svid.SVID, error) {
	tlsCert := s.getter()

	certificates, err := x509util.RawCertsToCertificates(tlsCert.Certificate)
	if err != nil {
		return nil, err
	}

	id, err := x509svid.IDFromCert(certificates[0])
	if err != nil {
		return nil, err
	}

	privateKey, ok := tlsCert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("agent certificate private key type %T is unexpectedly not a signer", tlsCert.PrivateKey)
	}

	return &x509svid.SVID{
		ID:           id,
		Certificates: certificates,
		PrivateKey:   privateKey,
	}, nil
}
