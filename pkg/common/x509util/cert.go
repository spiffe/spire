package x509util

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"

	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
)

func CertificateMatchesPublicKey(certificate *x509.Certificate, publicKey crypto.PublicKey) (bool, error) {
	return cryptoutil.PublicKeyEqual(certificate.PublicKey, publicKey)
}

func CertificateMatchesPrivateKey(certificate *x509.Certificate, privateKey crypto.PrivateKey) (bool, error) {
	return cryptoutil.KeyMatches(privateKey, certificate.PublicKey)
}

func CreateCertificate(ctx context.Context, km keymanager.KeyManager, template, parent *x509.Certificate, parentKeyID string, publicKey crypto.PublicKey) (*x509.Certificate, error) {
	parentPublicKey := parent.PublicKey
	if parentPublicKey == nil {
		// Pull the public key from the key manager. In the self-signing case, the
		// parent certificate PublicKey field is not likely to be set.
		var err error
		parentPublicKey, err = cryptoutil.GetPublicKey(ctx, km, parentKeyID)
		if err != nil {
			return nil, err
		}
	}

	signer := cryptoutil.NewKeyManagerSigner(km, parentKeyID, parentPublicKey)
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
