package identityprovider

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	identityproviderv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/identityprovider/v1"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/pkg/common/coretypes/jwtkey"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type X509Identity struct {
	CertChain  []*x509.Certificate
	PrivateKey crypto.PrivateKey
}

type X509IdentityFetcher interface {
	FetchX509Identity(context.Context) (*X509Identity, error)
}

type X509IdentityFetcherFunc func(context.Context) (*X509Identity, error)

func (fn X509IdentityFetcherFunc) FetchX509Identity(ctx context.Context) (*X509Identity, error) {
	return fn(ctx)
}

type Config struct {
	// TrustDomain is the server trust domain.
	TrustDomain spiffeid.TrustDomain
}

type Deps struct {
	// DataStore is used to retrieve the latest bundle. It MUST be set.
	DataStore datastore.DataStore

	// X509IdentityFetcher is used to fetch the X509 identity. It MUST be set.
	X509IdentityFetcher X509IdentityFetcher
}

type IdentityProvider struct {
	config Config

	mu   sync.RWMutex
	deps *Deps
}

func New(config Config) *IdentityProvider {
	return &IdentityProvider{
		config: config,
	}
}

func (s *IdentityProvider) SetDeps(deps Deps) error {
	switch {
	case deps.DataStore == nil:
		return errors.New("missing required DataStore dependency")
	case deps.X509IdentityFetcher == nil:
		return errors.New("missing required X509IdentityFetcher dependency")
	}
	s.mu.Lock()
	s.deps = &deps
	s.mu.Unlock()
	return nil
}

func (s *IdentityProvider) getDeps() (*Deps, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.deps == nil {
		return nil, status.Error(codes.FailedPrecondition, "IdentityProvider host service has not been initialized")
	}
	return s.deps, nil
}

func (s *IdentityProvider) V1() identityproviderv1.IdentityProviderServer {
	return &identityProviderV1{s: s}
}

type identityProviderV1 struct {
	identityproviderv1.UnsafeIdentityProviderServer

	s *IdentityProvider
}

func (v1 *identityProviderV1) FetchX509Identity(ctx context.Context, _ *identityproviderv1.FetchX509IdentityRequest) (*identityproviderv1.FetchX509IdentityResponse, error) {
	deps, err := v1.s.getDeps()
	if err != nil {
		return nil, err
	}

	bundle, err := deps.DataStore.FetchBundle(ctx, v1.s.config.TrustDomain.IDString())
	if err != nil {
		return nil, err
	}

	x509Authorities, err := x509certificate.ToPluginFromCommonProtos(bundle.RootCas)
	if err != nil {
		return nil, err
	}

	jwtAuthorities, err := jwtkey.ToPluginFromCommonProtos(bundle.JwtSigningKeys)
	if err != nil {
		return nil, err
	}

	x509Identity, err := deps.X509IdentityFetcher.FetchX509Identity(ctx)
	if err != nil {
		return nil, err
	}

	certChain := make([][]byte, 0, len(x509Identity.CertChain))
	for _, cert := range x509Identity.CertChain {
		certChain = append(certChain, cert.Raw)
	}

	privateKey, err := x509.MarshalPKCS8PrivateKey(x509Identity.PrivateKey)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	return &identityproviderv1.FetchX509IdentityResponse{
		Identity: &identityproviderv1.X509Identity{
			CertChain:  certChain,
			PrivateKey: privateKey,
		},
		Bundle: &plugintypes.Bundle{
			TrustDomain:     v1.s.config.TrustDomain.Name(),
			X509Authorities: x509Authorities,
			JwtAuthorities:  jwtAuthorities,
			RefreshHint:     bundle.RefreshHint,
			SequenceNumber:  bundle.SequenceNumber,
		},
	}, nil
}
