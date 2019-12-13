package identityprovider

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"sync"

	"github.com/spiffe/spire/proto/spire/server/datastore"
	"github.com/spiffe/spire/proto/spire/server/hostservices"
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
	// TrustDomainID of the server trust domain.
	TrustDomainID string
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

func (s *IdentityProvider) FetchX509Identity(ctx context.Context, req *hostservices.FetchX509IdentityRequest) (*hostservices.FetchX509IdentityResponse, error) {
	deps, err := s.getDeps()
	if err != nil {
		return nil, err
	}

	resp, err := deps.DataStore.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: s.config.TrustDomainID,
	})
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

	return &hostservices.FetchX509IdentityResponse{
		Identity: &hostservices.X509Identity{
			CertChain:  certChain,
			PrivateKey: privateKey,
		},
		Bundle: resp.Bundle,
	}, nil
}
