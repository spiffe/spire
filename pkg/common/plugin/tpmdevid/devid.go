package tpmdevid

import "crypto/rand"

const PluginName = "tpm_devid"

type AttestationRequest struct {
	DevIDCert [][]byte
	DevIDPub  []byte

	EKCert []byte
	EKPub  []byte

	AKPub []byte

	CertifiedDevID         []byte
	CertificationSignature []byte
}

type ChallengeRequest struct {
	DevID          []byte
	CredActivation *CredActivation
}

type CredActivation struct {
	Credential []byte
	Secret     []byte
}

type ChallengeResponse struct {
	DevID          []byte
	CredActivation []byte
}

func GetRandomBytes(size int) ([]byte, error) {
	rndBytes := make([]byte, size)
	_, err := rand.Read(rndBytes)
	if err != nil {
		return nil, err
	}
	return rndBytes, nil
}
