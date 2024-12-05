package tlspolicy

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyPolicy(t *testing.T) {
	require := require.New(t)

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	err := ApplyPolicy(tlsConfig, Policy{})
	require.NoError(err)

	require.Equal(0, len(tlsConfig.CurvePreferences))
	require.Equal(uint16(tls.VersionTLS12), tlsConfig.MinVersion)

	tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			x25519Kyber768Draft00, tls.CurveP256,
		},
	}
	err = ApplyPolicy(tlsConfig, Policy{
		RequirePQKEM: true,
	})
	require.NoError(err)

	require.Equal(tlsConfig.CurvePreferences, []tls.CurveID{x25519Kyber768Draft00})
	require.Equal(tlsConfig.MinVersion, uint16(tls.VersionTLS13))
}
