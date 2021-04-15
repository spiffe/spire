package fakeidentityprovider

import (
	"context"
	"errors"
	"sync"

	"github.com/spiffe/spire/proto/spire/common"
	identityproviderv0 "github.com/spiffe/spire/proto/spire/hostservice/server/identityprovider/v0"
)

type IdentityProvider struct {
	identityproviderv0.UnsafeIdentityProviderServer

	mu      sync.Mutex
	bundles []*common.Bundle
}

func New() *IdentityProvider {
	return &IdentityProvider{}
}

func (c *IdentityProvider) FetchX509Identity(ctx context.Context, req *identityproviderv0.FetchX509IdentityRequest) (*identityproviderv0.FetchX509IdentityResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.bundles) == 0 {
		return nil, errors.New("no bundle")
	}

	bundle := c.bundles[0]
	c.bundles = c.bundles[1:]

	// TODO: support sending back the identity
	return &identityproviderv0.FetchX509IdentityResponse{
		Bundle: bundle,
	}, nil
}

func (c *IdentityProvider) AppendBundle(bundle *common.Bundle) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bundles = append(c.bundles, bundle)
}
