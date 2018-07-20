package x509util

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/proto/server/keymanager"
)

func CertificateMatchesKey(certificate *x509.Certificate, publicKey crypto.PublicKey) (bool, error) {
	switch certPublicKey := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
		return ok && cryptoutil.RSAPublicKeyEqual(certPublicKey, rsaPublicKey), nil
	case *ecdsa.PublicKey:
		ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
		return ok && cryptoutil.ECDSAPublicKeyEqual(certPublicKey, ecdsaPublicKey), nil
	default:
		return false, fmt.Errorf("unsupported public key type %T", certificate.PublicKey)
	}
}

func CreateCertificate(ctx context.Context, km keymanager.KeyManager, template, parent *x509.Certificate, parentKeyId string, publicKey crypto.PublicKey) (*x509.Certificate, error) {
	parentPublicKey := parent.PublicKey
	if parentPublicKey == nil {
		// Pull the public key from the key manager. In the self-signing case, the
		// parent certificate PublicKey field is not likely to be set.
		var err error
		parentPublicKey, err = cryptoutil.GetPublicKey(ctx, km, parentKeyId)
		if err != nil {
			return nil, err
		}
	}

	signer := cryptoutil.NewKeyManagerSigner(km, parentKeyId, parentPublicKey)
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
