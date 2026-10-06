package witutil

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

// WITKeysFromProto converts WIT keys from the given []*types.WITKey to map[string]crypto.PublicKey.
// The key ID of the public key is used as the key in the returned map.
func WITKeysFromProto(proto []*types.WITKey) (map[string]crypto.PublicKey, error) {
	keys := make(map[string]crypto.PublicKey)
	for i, publicKey := range proto {
		witSigningKey, err := x509.ParsePKIXPublicKey(publicKey.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("unable to parse WIT signing key %d: %w", i, err)
		}
		keys[publicKey.KeyId] = witSigningKey
	}
	return keys, nil
}

// ProtoFromWITKeys converts WIT keys from the given map[string]crypto.PublicKey to []*types.WITKey
func ProtoFromWITKeys(keys map[string]crypto.PublicKey) ([]*types.WITKey, error) {
	var resp []*types.WITKey

	for kid, key := range keys {
		pkixBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal WIT public key: %w", err)
		}
		resp = append(resp, &types.WITKey{
			PublicKey: pkixBytes,
			KeyId:     kid,
		})
	}

	return resp, nil
}
