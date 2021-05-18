package tpmdevid

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/credactivation"
	devid "github.com/spiffe/spire/pkg/common/plugin/tpmdevid"
)

// We use a 32 bytes nonce to provide enough cryptographical randomness and to be
// consistent with other nonces sizes around the project.
const nonceSize = 32

func newDevIDChallenge() ([]byte, error) {
	nonce := make([]byte, nonceSize)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	return nonce, nil
}

func verifyDevIDChallenge(cert *x509.Certificate, challenge, response []byte) error {
	return cert.CheckSignature(cert.SignatureAlgorithm, challenge, response)
}

func newCredActivationChallenge(akPub, ekPub tpm2.Public) (*devid.CredActivation, []byte, error) {
	akName, err := akPub.Name()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot extract name from AK public")
	}

	hash, err := ekPub.NameAlg.Hash()
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, hash.Size())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, nil, err
	}

	encKey, err := ekPub.Key()
	if err != nil {
		return nil, nil, err
	}

	var symBlockSize int
	switch encKey.(type) {
	case *rsa.PublicKey:
		symBlockSize = int(ekPub.RSAParameters.Symmetric.KeyBits) / 8

	default:
		return nil, nil, errors.New("unsupported algorithm")
	}

	credentialBlob, secret, err := credactivation.Generate(
		akName.Digest,
		encKey,
		symBlockSize,
		nonce,
	)
	if err != nil {
		return nil, nil, err
	}

	return &devid.CredActivation{
		Credential: credentialBlob[2:],
		Secret:     secret[2:],
	}, nonce, err
}

func verifyCredActivationChallenge(expectedNonce, responseNonce []byte) error {
	if !bytes.Equal(expectedNonce, responseNonce) {
		return errors.New("nonces are different")
	}

	return nil
}
