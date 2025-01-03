package jwtutil

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

// JWTKeysFromProto converts JWT keys from the given []*types.JWTKey to map[string]crypto.PublicKey.
// The key ID of the public key is used as the key in the returned map.
func JWTKeysFromProto(proto []*types.JWTKey) (map[string]crypto.PublicKey, error) {
	keys := make(map[string]crypto.PublicKey)
	for i, publicKey := range proto {
		jwtSigningKey, err := x509.ParsePKIXPublicKey(publicKey.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("unable to parse JWT signing key %d: %w", i, err)
		}
		keys[publicKey.KeyId] = jwtSigningKey
	}
	return keys, nil
}

// ProtoFromJWTKeys converts JWT keys from the given map[string]crypto.PublicKey to []*types.JWTKey
func ProtoFromJWTKeys(keys map[string]crypto.PublicKey) ([]*types.JWTKey, error) {
	var resp []*types.JWTKey

	for kid, key := range keys {
		pkixBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, err
		}
		resp = append(resp, &types.JWTKey{
			PublicKey: pkixBytes,
			KeyId:     kid,
		})
	}

	return resp, nil
}
