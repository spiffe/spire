package awsiid

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/awsiid/awsrsa1024"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/awsiid/awsrsa2048"
)

func TestGetAWSCACertificate(t *testing.T) {
	// Every region in the RSA-2048 map must produce a valid, parseable certificate
	require.NotEmpty(t, awsrsa2048.CACerts)
	for region := range awsrsa2048.CACerts {
		t.Run(fmt.Sprintf("RSA2048/%s", region), func(t *testing.T) {
			cert, err := getAWSCACertificate(region, RSA2048)
			require.NoError(t, err)
			assert.NotNil(t, cert)
		})
	}

	// Every region in the RSA-1024 map must produce a valid, parseable certificate
	require.NotEmpty(t, awsrsa1024.CACerts)
	for region := range awsrsa1024.CACerts {
		t.Run(fmt.Sprintf("RSA1024/%s", region), func(t *testing.T) {
			cert, err := getAWSCACertificate(region, RSA1024)
			require.NoError(t, err)
			assert.NotNil(t, cert)
		})
	}

	// RSA-1024 falls back to a default cert for regions not in its map
	t.Run("RSA1024/default_fallback", func(t *testing.T) {
		cert, err := getAWSCACertificate("us-east-1", RSA1024)
		require.NoError(t, err)
		assert.NotNil(t, cert)
	})

	// RSA-2048 has no fallback — unknown regions must error
	t.Run("RSA2048/unknown_region", func(t *testing.T) {
		_, err := getAWSCACertificate("xx-fake-1", RSA2048)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported region")
	})

	// Unset key type must error
	t.Run("unset_key_type", func(t *testing.T) {
		_, err := getAWSCACertificate("us-east-1", KeyTypeUnset)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unset")
	})
}
