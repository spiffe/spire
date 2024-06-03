package cache

import (
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// WorkloadUpdate is used to convey workload information to cache subscribers
type WorkloadUpdate struct {
	Identities       []Identity
	Bundle           *spiffebundle.Bundle
	FederatedBundles map[spiffeid.TrustDomain]*spiffebundle.Bundle
}

func (u *WorkloadUpdate) HasIdentity() bool {
	return len(u.Identities) > 0
}
