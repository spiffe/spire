package tpmdevid

const PluginName = "tpm_devid"

type AttestationRequest struct {
	DevIDCert []byte
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
