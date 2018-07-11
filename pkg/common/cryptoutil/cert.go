package cryptoutil

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/spiffe/spire/proto/server/keymanager"
)

func CreateCertificate(ctx context.Context, km keymanager.KeyManager, template, parent *x509.Certificate, parentKeyId string, publicKey crypto.PublicKey) (*x509.Certificate, error) {
	parentPublicKey := parent.PublicKey
	if parentPublicKey == nil {
		// Pull the public key from the key manager. In the self-signing case, the
		// parent certificate PublicKey field is not likely to be set.
		var err error
		parentPublicKey, err = GetPublicKey(ctx, km, parentKeyId)
		if err != nil {
			return nil, err
		}
	}

	signer := NewKeyManagerSigner(km, parentKeyId, parentPublicKey)
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signer)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return cert, nil
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
