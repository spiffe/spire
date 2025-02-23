package cache

import (
	"crypto"
	"crypto/x509"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/proto/spire/common"
)

type Selectors []*common.Selector

// Identity holds the data for a single workload identity
type Identity struct {
	Entry      *common.RegistrationEntry
	X509SVID   []*x509.Certificate
	PrivateKey crypto.Signer
}

// UpdateSVIDs holds information for an SVIDs update to the cache.
type UpdateSVIDs[SVID interface{}] struct {
	// SVIDs is a set of updated SVIDs that should be merged into
	// the cache, keyed by registration entry id.
	SVIDs map[string]SVID
}

// WorkloadUpdate is used to convey workload information to cache subscribers
type WorkloadUpdate struct {
	Identities       []Identity
	Bundle           *spiffebundle.Bundle
	FederatedBundles map[spiffeid.TrustDomain]*spiffebundle.Bundle
}

func (u *WorkloadUpdate) HasIdentity() bool {
	return len(u.Identities) > 0
}

type commonSVID interface {
	MakeIdentity(record *lruCacheRecord) Identity
	Expiry() time.Time
}

// X509SVID holds onto the SVID certificate chain and private key.
type X509SVID struct {
	Chain      []*x509.Certificate
	PrivateKey crypto.Signer
}

func (x *X509SVID) MakeIdentity(record *lruCacheRecord) Identity {
	return Identity{
		Entry:      record.entry,
		X509SVID:   x.Chain,
		PrivateKey: x.PrivateKey,
	}
}

func (x *X509SVID) Expiry() time.Time {
	return x.Chain[0].NotAfter
}
