package keymanagerbase

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/keymanager/v1"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestNewSetsConfigDefaults(t *testing.T) {
	// This test makes sure that we wire up the default functions
	b := New(Config{})
	assert.Equal(t, defaultGenerator{}, b.config.Generator)
	assert.Nil(t, b.config.WriteEntries)
}

func TestSignDataHashAlgorithm(t *testing.T) {
	ctx := context.Background()
	b := New(Config{})
	for _, keyType := range []keymanagerv1.KeyType{keymanagerv1.KeyType_EC_P256, keymanagerv1.KeyType_ML_DSA_44} {
		_, err := b.GenerateKey(ctx, &keymanagerv1.GenerateKeyRequest{KeyId: keyType.String(), KeyType: keyType})
		require.NoError(t, err)
	}

	data := []byte("DATA")
	digest := sha256.Sum256(data)

	for _, tt := range []struct {
		name          string
		keyID         string
		data          []byte
		hashAlgorithm keymanagerv1.HashAlgorithm
		expectCode    codes.Code
		expectMessage string
	}{
		{
			name:          "EC key with hash",
			keyID:         "EC_P256",
			data:          digest[:],
			hashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
		},
		{
			name:          "EC key without hash",
			keyID:         "EC_P256",
			data:          digest[:],
			expectCode:    codes.InvalidArgument,
			expectMessage: "hash algorithm is required",
		},
		{
			name:  "ML-DSA key without hash",
			keyID: "ML_DSA_44",
			data:  data,
		},
		{
			name:          "ML-DSA key with hash",
			keyID:         "ML_DSA_44",
			data:          digest[:],
			hashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
			expectCode:    codes.InvalidArgument,
			expectMessage: "hash algorithm must be unspecified for ML-DSA keys",
		},
		{
			name:          "no such key",
			keyID:         "nope",
			data:          data,
			expectCode:    codes.NotFound,
			expectMessage: "no such key",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := b.SignData(ctx, &keymanagerv1.SignDataRequest{
				KeyId:      tt.keyID,
				Data:       tt.data,
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{HashAlgorithm: tt.hashAlgorithm},
			})
			spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMessage)
			if tt.expectCode != codes.OK {
				return
			}

			pubResp, err := b.GetPublicKey(ctx, &keymanagerv1.GetPublicKeyRequest{KeyId: tt.keyID})
			require.NoError(t, err)
			publicKey, err := x509.ParsePKIXPublicKey(pubResp.PublicKey.PkixData)
			require.NoError(t, err)
			if mldsaKey, ok := publicKey.(*mldsa.PublicKey); ok {
				require.NoError(t, mldsa.Verify(mldsaKey, tt.data, resp.Signature, nil))
			}
		})
	}
}

func TestSignDataPSSOptionsWithMLDSAKey(t *testing.T) {
	ctx := context.Background()
	b := New(Config{})
	_, err := b.GenerateKey(ctx, &keymanagerv1.GenerateKeyRequest{KeyId: "id", KeyType: keymanagerv1.KeyType_ML_DSA_44})
	require.NoError(t, err)

	_, err = b.SignData(ctx, &keymanagerv1.SignDataRequest{
		KeyId: "id",
		Data:  []byte("DATA"),
		SignerOpts: &keymanagerv1.SignDataRequest_PssOptions{
			PssOptions: &keymanagerv1.SignDataRequest_PSSOptions{
				HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
				SaltLength:    32,
			},
		},
	})
	spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "PSS options are not supported for ML-DSA keys")
}

func TestMakeKeyEntryFromMLDSAKey(t *testing.T) {
	for params, keyType := range map[mldsa.Parameters]keymanagerv1.KeyType{
		mldsa.MLDSA44(): keymanagerv1.KeyType_ML_DSA_44,
		mldsa.MLDSA65(): keymanagerv1.KeyType_ML_DSA_65,
		mldsa.MLDSA87(): keymanagerv1.KeyType_ML_DSA_87,
	} {
		t.Run(params.String(), func(t *testing.T) {
			key, err := mldsa.GenerateKey(params)
			require.NoError(t, err)
			entry, err := MakeKeyEntryFromKey("id", key)
			require.NoError(t, err)
			require.Equal(t, keyType, entry.Type)
			require.Equal(t, crypto.Signer(key), entry.PrivateKey)
		})
	}
}
