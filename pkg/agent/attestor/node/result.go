package attestor

import (
	"crypto/x509"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
)

// Allow AttestationResult to be used as go-spiffe SVID and bundle sources.
// TODO(arndt): Check whether the key of the agent is ok to be exposed to other parties.
var (
	_ x509svid.Source   = (*AttestationResult)(nil)
	_ x509bundle.Source = (*AttestationResult)(nil)
)

type AttestationResult struct {
	SVID         []*x509.Certificate
	Key          keymanager.Key
	Bundle       *spiffebundle.Bundle
	Reattestable bool
}

func (ar *AttestationResult) GetX509SVID() (*x509svid.SVID, error) {
	return &x509svid.SVID{
		Certificates: ar.SVID,
		PrivateKey:   ar.Key,
	}, nil
}

func (ar *AttestationResult) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	if ar.Bundle.TrustDomain() != trustDomain {
		return nil, fmt.Errorf("bundle for trust domain %q not found", trustDomain)
	}
	return ar.Bundle.X509Bundle(), nil
}
