package witutil

import (
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
)

func TestWITKeysFromProto(t *testing.T) {
	publicKey := testkey.MustEC256().Public()
	pkixBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)

	for _, tt := range []struct {
		name        string
		proto       []*types.WITKey
		expectKeys  map[string]crypto.PublicKey
		expectError string
	}{
		{
			name:       "no keys",
			expectKeys: map[string]crypto.PublicKey{},
		},
		{
			name: "success",
			proto: []*types.WITKey{
				{KeyId: "key-id-1", PublicKey: pkixBytes},
			},
			expectKeys: map[string]crypto.PublicKey{"key-id-1": publicKey},
		},
		{
			name: "malformed public key",
			proto: []*types.WITKey{
				{KeyId: "key-id-1", PublicKey: pkixBytes},
				{KeyId: "key-id-2", PublicKey: []byte("malformed")},
			},
			expectError: "unable to parse WIT signing key 1: asn1: structure error:",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := WITKeysFromProto(tt.proto)

			if tt.expectError != "" {
				require.ErrorContains(t, err, tt.expectError)
				require.Nil(t, keys)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expectKeys, keys)
		})
	}
}

func TestProtoFromWITKeys(t *testing.T) {
	publicKey := testkey.MustEC256().Public()
	pkixBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)

	for _, tt := range []struct {
		name        string
		keys        map[string]crypto.PublicKey
		expectProto []*types.WITKey
		expectError string
	}{
		{
			name: "no keys",
		},
		{
			name: "success",
			keys: map[string]crypto.PublicKey{"key-id-1": publicKey},
			expectProto: []*types.WITKey{
				{KeyId: "key-id-1", PublicKey: pkixBytes},
			},
		},
		{
			name:        "unsupported public key type",
			keys:        map[string]crypto.PublicKey{"key-id-1": "not a public key"},
			expectError: "failed to marshal WIT public key: x509: unsupported public key type: string",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			proto, err := ProtoFromWITKeys(tt.keys)

			if tt.expectError != "" {
				require.EqualError(t, err, tt.expectError)
				require.Nil(t, proto)
				return
			}

			require.NoError(t, err)
			spiretest.AssertProtoListEqual(t, tt.expectProto, proto)
		})
	}
}
