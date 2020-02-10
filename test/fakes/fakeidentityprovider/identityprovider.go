package fakeidentityprovider

import (
	"context"
	"errors"
	"sync"

	"github.com/spiffe/spire/pkg/server/plugin/hostservices"
	"github.com/spiffe/spire/proto/spire/common"
)

type IdentityProvider struct {
	mu      sync.Mutex
	bundles []*common.Bundle
}

func New() *IdentityProvider {
	return &IdentityProvider{}
}

func (c *IdentityProvider) FetchX509Identity(ctx context.Context, req *hostservices.FetchX509IdentityRequest) (*hostservices.FetchX509IdentityResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.bundles) == 0 {
		return nil, errors.New("no bundle")
	}

	bundle := c.bundles[0]
	c.bundles = c.bundles[1:]

	// TODO: support sending back the identity
	return &hostservices.FetchX509IdentityResponse{
		Bundle: bundle,
	}, nil
}

func (c *IdentityProvider) AppendBundle(bundle *common.Bundle) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bundles = append(c.bundles, bundle)
}
