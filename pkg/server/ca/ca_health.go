package ca

import (
	"context"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/pemutil"
)

var (
	caHealthKey, _ = pemutil.ParsePublicKey([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzLY1/SRlsMJExTnuvzBO292RjGjU
3L8jFRtmQl0CjBeHdxUlGK1OkNLDYh0b6AW4siWt+y+DcbUAWNb14e5zWg==
-----END PUBLIC KEY-----`))
)

type caHealth struct {
	ca ServerCA
	td spiffeid.TrustDomain
}

func (h *caHealth) CheckHealth() health.State {
	// Prevent a problem with signing the SVID from blocking the health check
	// indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	ctx = health.CheckContext(ctx)

	spiffeID, err := spiffeid.FromPath(h.td, "/for/health/check/only")
	if err == nil {
		_, err = h.ca.SignWorkloadX509SVID(ctx, WorkloadX509SVIDParams{
			SPIFFEID:  spiffeID,
			PublicKey: caHealthKey,
		})
	}

	// Both liveness and readiness are determined by whether or not the
	// x509 CA was successfully signed.
	ready := err == nil
	live := err == nil

	return health.State{
		Live:  live,
		Ready: ready,
		ReadyDetails: caHealthDetails{
			SignX509SVIDErr: errString(err),
		},
		LiveDetails: caHealthDetails{
			SignX509SVIDErr: errString(err),
		},
	}
}

type caHealthDetails struct {
	SignX509SVIDErr string `json:"sign_x509_svid_err,omitempty"`
}

func errString(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
