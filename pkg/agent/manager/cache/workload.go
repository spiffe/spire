package cache

import (
	"crypto"
	"crypto/x509"

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

// X509SVID holds onto the SVID certificate chain and private key.
type X509SVID struct {
	Chain      []*x509.Certificate
	PrivateKey crypto.Signer
}
