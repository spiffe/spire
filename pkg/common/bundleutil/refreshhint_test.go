package bundleutil

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

func TestCalculateRefreshHint(t *testing.T) {
	trustDomain := spiffeid.RequireTrustDomainFromString("domain.test")
	emptyBundle := spiffebundle.New(trustDomain)
	emptyBundleWithRefreshHint := spiffebundle.New(trustDomain)
	emptyBundleWithRefreshHint.SetRefreshHint(time.Hour * 1)

	now := time.Now()
	bundleWithCerts := spiffebundle.New(trustDomain)
	bundleWithCerts.AddX509Authority(&x509.Certificate{
		Raw:       []byte{1},
		NotBefore: now,
		NotAfter:  now.Add(time.Hour * 2),
	})
	bundleWithCerts.AddX509Authority(&x509.Certificate{
		Raw:       []byte{2},
		NotBefore: now,
		NotAfter:  now.Add(time.Hour),
	})
	bundleWithCerts.AddX509Authority(&x509.Certificate{
		Raw:       []byte{3},
		NotBefore: now,
		NotAfter:  now.Add(time.Hour * 3),
	})

	testCases := []struct {
		name        string
		bundle      *spiffebundle.Bundle
		refreshHint time.Duration
	}{
		{
			name:        "empty bundle with no refresh hint",
			bundle:      emptyBundle,
			refreshHint: MinimumRefreshHint,
		},
		{
			name:        "empty bundle with refresh hint",
			bundle:      emptyBundleWithRefreshHint,
			refreshHint: time.Hour,
		},
		{
			// the bundle has a few certs. the lowest lifetime is 1 hour.
			// so we expect to get back a fraction of that time.
			name:        "bundle with certs",
			bundle:      bundleWithCerts,
			refreshHint: time.Hour / refreshHintLeewayFactor,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.refreshHint, CalculateRefreshHint(testCase.bundle), "refresh hint is wrong")
		})
	}
}
