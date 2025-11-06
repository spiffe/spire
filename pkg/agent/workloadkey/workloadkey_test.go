package workloadkey_test

import (
	"testing"

	"github.com/spiffe/spire/pkg/agent/workloadkey"
	"github.com/stretchr/testify/require"
)

func TestKeyTypeFromString(t *testing.T) {
	for _, tt := range []struct {
		name          string
		keyType       string
		expectKeyType workloadkey.KeyType
		errMsg        string
	}{
		{
			name:          "RSA 2048",
			keyType:       "rsa-2048",
			expectKeyType: workloadkey.RSA2048,
		},
		{
			name:          "EC 256",
			keyType:       "ec-p256",
			expectKeyType: workloadkey.ECP256,
		},
		{
			name:          "EC 384",
			keyType:       "ec-p384",
			expectKeyType: workloadkey.ECP384,
		},
		{
			name:          "unsupported type",
			keyType:       "Unsupported",
			expectKeyType: workloadkey.KeyTypeUnset,
			errMsg:        "key type \"Unsupported\" is unknown; must be one of [rsa-2048, ec-p256, ec-p384]",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			keyType, err := workloadkey.KeyTypeFromString(tt.keyType)

			require.Equal(t, tt.expectKeyType, keyType)

			if tt.errMsg != "" {
				require.EqualError(t, err, tt.errMsg)
				return
			}

			require.NoError(t, err)
		})
	}
}
