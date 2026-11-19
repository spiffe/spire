package workloadkey_test

import (
	"crypto/mldsa"
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
			name:          "ML-DSA-44",
			keyType:       "ml-dsa-44",
			expectKeyType: workloadkey.MLDSA44,
		},
		{
			name:          "ML-DSA-65",
			keyType:       "ml-dsa-65",
			expectKeyType: workloadkey.MLDSA65,
		},
		{
			name:          "ML-DSA-87",
			keyType:       "ML-DSA-87",
			expectKeyType: workloadkey.MLDSA87,
		},
		{
			name:          "unsupported type",
			keyType:       "Unsupported",
			expectKeyType: workloadkey.KeyTypeUnset,
			errMsg:        "key type \"Unsupported\" is unknown; must be one of [rsa-2048, ec-p256, ec-p384, ml-dsa-44, ml-dsa-65, ml-dsa-87]",
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

func TestMLDSAKeyTypes(t *testing.T) {
	for _, tt := range []struct {
		keyType workloadkey.KeyType
		params  mldsa.Parameters
		name    string
		alg     string
	}{
		{keyType: workloadkey.MLDSA44, params: mldsa.MLDSA44(), name: "ml-dsa-44", alg: "ML-DSA-44"},
		{keyType: workloadkey.MLDSA65, params: mldsa.MLDSA65(), name: "ml-dsa-65", alg: "ML-DSA-65"},
		{keyType: workloadkey.MLDSA87, params: mldsa.MLDSA87(), name: "ml-dsa-87", alg: "ML-DSA-87"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.name, tt.keyType.String())

			alg, err := tt.keyType.SigningAlgorithm()
			require.NoError(t, err)
			require.Equal(t, tt.alg, alg)

			signer, err := tt.keyType.GenerateSigner()
			require.NoError(t, err)
			key, ok := signer.(*mldsa.PrivateKey)
			require.True(t, ok)
			require.Equal(t, tt.params, key.PublicKey().Parameters())
		})
	}
}
