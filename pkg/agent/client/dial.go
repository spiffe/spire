package client

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/x509util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	defaultDialTimeout      = 30 * time.Second
	roundRobinServiceConfig = `{ "loadBalancingConfig": [ { "round_robin": {} } ] }`
)

type DialServerConfig struct {
	// Address is the SPIRE server address
	Address string

	TrustDomain spiffeid.TrustDomain

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

	ctx, cancel := context.WithTimeout(ctx, defaultDialTimeout)
	defer cancel()

	if config.dialContext == nil {
		config.dialContext = grpc.DialContext
	}
	client, err := config.dialContext(ctx, config.Address,
		grpc.WithDefaultServiceConfig(roundRobinServiceConfig),
		grpc.WithDisableServiceConfig(),
		grpc.FailOnNonTempDialError(true),
		grpc.WithBlock(),
		grpc.WithReturnConnectionError(),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
	switch {
	case err == nil:
	case errors.Is(err, context.Canceled):
		return nil, fmt.Errorf("failed to dial %s: canceled", config.Address)
	case errors.Is(err, context.DeadlineExceeded):
		return nil, fmt.Errorf("failed to dial %s: timed out", config.Address)
	default:
		return nil, fmt.Errorf("failed to dial %s: %w", config.Address, err)
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
