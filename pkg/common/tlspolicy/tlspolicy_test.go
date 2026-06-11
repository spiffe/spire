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
			tls.X25519MLKEM768, tls.CurveP256,
		},
	}
	err = ApplyPolicy(tlsConfig, Policy{
		RequirePQKEM: true,
	})
	require.NoError(err)

	require.Equal([]tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024}, tlsConfig.CurvePreferences)
	require.Equal(uint16(tls.VersionTLS13), tlsConfig.MinVersion)
}
