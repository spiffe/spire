package aws

const (
	// PluginName for AWS IID
	PluginName = "aws_iid"
)

// IIDAttestationData AWS IID attestation data
type IIDAttestationData struct {
	Document         string `json:"document"`
	Signature        string `json:"signature"`
	SignatureRSA2048 string `json:"rsa2048"`
}
