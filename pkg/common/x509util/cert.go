package x509util

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"

	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/proto/server/keymanager"
)

func CertificateMatchesKey(certificate *x509.Certificate, publicKey crypto.PublicKey) (bool, error) {
	return cryptoutil.PublicKeyEqual(certificate.PublicKey, publicKey)
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

func DERFromCertificates(certs []*x509.Certificate) (derBytes []byte) {
	for _, cert := range certs {
		derBytes = append(derBytes, cert.Raw...)
	}
	return derBytes
}
