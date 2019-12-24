package bundleutil

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/require"
)

func TestCalculateRefreshHint(t *testing.T) {
	emptyBundle := New("domain.test")

	emptyBundleWithRefreshHint, err := BundleFromProto(&common.Bundle{
		TrustDomainId: "domain.test",
		RefreshHint:   3600,
	})
	require.NoError(t, err)

	now := time.Now()
	bundleWithCerts := New("domain.test")
	bundleWithCerts.AppendRootCA(&x509.Certificate{
		NotBefore: now,
		NotAfter:  now.Add(time.Hour * 2),
	})
	bundleWithCerts.AppendRootCA(&x509.Certificate{
		NotBefore: now,
		NotAfter:  now.Add(time.Hour),
	})
	bundleWithCerts.AppendRootCA(&x509.Certificate{
		NotBefore: now,
		NotAfter:  now.Add(time.Hour * 3),
	})

	testCases := []struct {
		name        string
		bundle      *Bundle
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
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.refreshHint, CalculateRefreshHint(testCase.bundle), "refresh hint is wrong")
		})
	}
}
