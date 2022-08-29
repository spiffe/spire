package ca

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire/pkg/common/pemutil"
)

var (
	validationPubkey, _ = pemutil.ParsePublicKey([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzLY1/SRlsMJExTnuvzBO292RjGjU
3L8jFRtmQl0CjBeHdxUlGK1OkNLDYh0b6AW4siWt+y+DcbUAWNb14e5zWg==
-----END PUBLIC KEY-----`))
)

type X509CAValidator struct {
	TrustDomain spiffeid.TrustDomain
	Signer      crypto.Signer
}

func (v X509CAValidator) ValidateUpstreamX509CA(x509CA, upstreamRoots []*x509.Certificate) error {
	return v.validateX509CA(x509CA[0], upstreamRoots, x509CA)
}
func (v X509CAValidator) ValidateSelfSignedX509CA(x509CA *x509.Certificate) error {
	return v.validateX509CA(x509CA, []*x509.Certificate{x509CA}, nil)
}

func (v X509CAValidator) validateX509CA(x509CA *x509.Certificate, x509Roots, upstreamChain []*x509.Certificate) error {
	spiffeID, err := spiffeid.FromPath(v.TrustDomain, "/spire/throwaway")
	if err != nil {
		return fmt.Errorf("unexpected error making ID for validation: %w", err)
	}
	params := X509SVIDParams{
		SpiffeID:  spiffeID,
		PublicKey: validationPubkey,
	}

	bundle := x509bundle.FromX509Authorities(v.TrustDomain, x509Roots)

	svid, err := signX509SVID(v.TrustDomain, &X509CA{
		Signer:        v.Signer,
		Certificate:   x509CA,
		UpstreamChain: upstreamChain,
	}, params, x509CA.NotBefore, x509CA.NotAfter, false)
	if err != nil {
		return fmt.Errorf("unable to sign throwaway SVID for X509 CA validation: %w", err)
	}

	if _, _, err := x509svid.Verify(svid, bundle); err != nil {
		return fmt.Errorf("X509 CA produced an invalid X509-SVID chain: %w", err)
	}
	return nil
}
