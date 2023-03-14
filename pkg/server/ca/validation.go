package ca

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"math/big"
	"net/url"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/credvalidator"
)

var (
	validationPubkey, _ = pemutil.ParsePublicKey([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzLY1/SRlsMJExTnuvzBO292RjGjU
3L8jFRtmQl0CjBeHdxUlGK1OkNLDYh0b6AW4siWt+y+DcbUAWNb14e5zWg==
-----END PUBLIC KEY-----`))
)

type X509CAValidator struct {
	TrustDomain   spiffeid.TrustDomain
	CredValidator *credvalidator.Validator
	Signer        crypto.Signer
	Clock         clock.Clock
}

func (v *X509CAValidator) ValidateUpstreamX509CA(x509CA, upstreamRoots []*x509.Certificate) error {
	return v.validateX509CA(x509CA[0], upstreamRoots, x509CA)
}

func (v *X509CAValidator) ValidateSelfSignedX509CA(x509CA *x509.Certificate) error {
	return v.validateX509CA(x509CA, []*x509.Certificate{x509CA}, nil)
}

func (v *X509CAValidator) validateX509CA(x509CA *x509.Certificate, x509Roots, upstreamChain []*x509.Certificate) error {
	if err := v.CredValidator.ValidateX509CA(x509CA); err != nil {
		return fmt.Errorf("invalid upstream-signed X509 CA: %w", err)
	}

	spiffeID, err := spiffeid.FromPath(v.TrustDomain, "/spire/throwaway")
	if err != nil {
		return fmt.Errorf("unexpected error making ID for validation: %w", err)
	}

	bundle := x509bundle.FromX509Authorities(v.TrustDomain, x509Roots)

	svid, err := x509util.CreateCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotAfter:     x509CA.NotAfter,
		NotBefore:    x509CA.NotBefore,
		URIs:         []*url.URL{spiffeID.URL()},
	}, x509CA, validationPubkey, v.Signer)
	if err != nil {
		return fmt.Errorf("failed to sign validation certificate: %w", err)
	}

	svidChain := append([]*x509.Certificate{svid}, upstreamChain...)

	if _, _, err := x509svid.Verify(svidChain, bundle); err != nil {
		return fmt.Errorf("X509 CA produced an invalid X509-SVID chain: %w", err)
	}
	return nil
}
