package tlspolicy

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyPolicy(t *testing.T) {
	require := require.New(t)

	tlsConfig := &tls.Config{}
	err := ApplyPolicy(tlsConfig, Policy{})
	require.NoError(err)

	require.Equal(len(tlsConfig.CurvePreferences), 0)
	require.Equal(tlsConfig.MinVersion, uint16(0))

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

	require.Equal([]tls.CurveID{x25519Kyber768Draft00}, tlsConfig.CurvePreferences)
	require.Equal(uint16(tls.VersionTLS13), tlsConfig.MinVersion)
}
