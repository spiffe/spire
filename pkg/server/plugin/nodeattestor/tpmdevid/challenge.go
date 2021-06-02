package tpmdevid

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/credactivation"
	devid "github.com/spiffe/spire/pkg/common/plugin/tpmdevid"
)

func newNonce(size int) ([]byte, error) {
	nonce, err := devid.GetRandomBytes(size)
	if err != nil {
		return nil, err
	}

	return nonce, nil
}

func VerifyDevIDChallenge(cert *x509.Certificate, challenge, response []byte) error {
	var signAlg x509.SignatureAlgorithm
	switch publicKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		signAlg = x509.SHA256WithRSA
	case *ecdsa.PublicKey:
		signAlg = x509.ECDSAWithSHA256
	default:
		return fmt.Errorf("unsupported private key type %T", publicKey)
	}
	return cert.CheckSignature(signAlg, challenge, response)
}

func NewCredActivationChallenge(akPub, ekPub tpm2.Public) (*devid.CredActivation, []byte, error) {
	akName, err := akPub.Name()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot extract name from AK public: %w", err)
	}

	hash, err := ekPub.NameAlg.Hash()
	if err != nil {
		return nil, nil, err
	}

	nonce, err := newNonce(hash.Size())
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

func VerifyCredActivationChallenge(expectedNonce, responseNonce []byte) error {
	if !bytes.Equal(expectedNonce, responseNonce) {
		return errors.New("nonces are different")
	}

	return nil
}
