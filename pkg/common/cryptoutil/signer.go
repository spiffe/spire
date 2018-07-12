package cryptoutil

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/spiffe/spire/proto/server/keymanager"
)

type KeyManagerSigner struct {
	km        keymanager.KeyManager
	keyId     string
	publicKey crypto.PublicKey
}

var _ crypto.Signer = (*KeyManagerSigner)(nil)

func NewKeyManagerSigner(km keymanager.KeyManager, keyId string, publicKey crypto.PublicKey) *KeyManagerSigner {
	return &KeyManagerSigner{
		km:        km,
		keyId:     keyId,
		publicKey: publicKey,
	}
}

func (s *KeyManagerSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *KeyManagerSigner) SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	resp, err := s.km.SignData(ctx, &keymanager.SignDataRequest{
		KeyId:         s.keyId,
		Data:          digest,
		HashAlgorithm: keymanager.HashAlgorithm(opts.HashFunc()),
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Signature) == 0 {
		return nil, fmt.Errorf("response missing signature data")
	}
	return resp.Signature, nil
}

func (s *KeyManagerSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// rand is purposefully ignored since it can't be communicated between
	// the plugin boundary. The crypto.Signer interface implies this is ok
	// when it says "possibly using entropy from rand".
	return s.SignContext(context.Background(), digest, opts)
}

func GenerateKeyAndSigner(ctx context.Context, km keymanager.KeyManager, keyId string, algorithm keymanager.KeyAlgorithm) (*KeyManagerSigner, error) {
	resp, err := km.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:        keyId,
		KeyAlgorithm: algorithm,
	})
	if err != nil {
		return nil, err
	}
	publicKey, err := x509.ParsePKIXPublicKey(resp.PublicKey.PkixData)
	if err != nil {
		return nil, fmt.Errorf("unable to parse public key pkix data: %v", err)
	}
	return NewKeyManagerSigner(km, keyId, publicKey), nil
}
