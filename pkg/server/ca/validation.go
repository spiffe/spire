package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

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

func (v X509CAValidator) ValidateX509CA(ctx context.Context, x509CA, upstreamRoots []*x509.Certificate) error {
	params := X509SVIDParams{
		SpiffeID:  v.TrustDomain.NewID("/spire/throwaway"),
		PublicKey: validationPubkey,
	}

	var bundle *x509bundle.Bundle
	var upstreamChain []*x509.Certificate
	if len(upstreamRoots) > 0 {
		// If there are upstream roots, this is an upstream signed intermediate
		// CA, so set the bundle to the upstream roots and set the upstream
		// chain appropriately.
		bundle = x509bundle.FromX509Authorities(v.TrustDomain, upstreamRoots)
		upstreamChain = x509CA
	} else {
		// If there are no upstream roots, this is a self-signed CA so set
		// the bundle to the CA itself and don't set the upstream chain.
		bundle = x509bundle.FromX509Authorities(v.TrustDomain, x509CA)
	}

	now := time.Now()
	svid, err := SignX509SVID(ctx, v.TrustDomain, &X509CA{
		Signer:        v.Signer,
		Certificate:   x509CA[0],
		UpstreamChain: upstreamChain,
	}, params, now, now.Add(5*time.Minute))
	if err != nil {
		return fmt.Errorf("unable to sign throwaway SVID for X509 CA validation: %w", err)
	}

	if _, _, err := x509svid.Verify(svid, bundle); err != nil {
		return fmt.Errorf("X509 CA produced an invalid X509-SVID chain: %w", err)
	}
	return nil
}
