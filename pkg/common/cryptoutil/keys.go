package cryptoutil

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/spiffe/spire/proto/server/keymanager"
)

func RSAPublicKeyEqual(a, b *rsa.PublicKey) bool {
	return a.E == b.E && a.N.Cmp(b.N) == 0
}

func ECDSAPublicKeyEqual(a, b *ecdsa.PublicKey) bool {
	return a.Curve == b.Curve && a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0
}

func ECDSAKeyMatches(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) bool {
	return ECDSAPublicKeyEqual(&privateKey.PublicKey, publicKey)
}

func GetPublicKey(ctx context.Context, km keymanager.KeyManager, keyId string) (crypto.PublicKey, error) {
	resp, err := km.GetPublicKey(ctx, &keymanager.GetPublicKeyRequest{
		KeyId: keyId,
	})
	if err != nil {
		return nil, err
	}
	if resp.PublicKey == nil {
		return nil, errors.New("response missing public key")
	}
	publicKey, err := x509.ParsePKIXPublicKey(resp.PublicKey.PkixData)
	if err != nil {
		return nil, fmt.Errorf("unable to parse public key pkix data: %v", err)
	}
	return publicKey, nil
}
