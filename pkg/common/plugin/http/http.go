package http

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint: gosec // SHA1 use is according to specification
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/spiffe/spire/pkg/common/idutil"
)

const (
	nonceLen = 32

	// PluginName for http based attestor
	PluginName = "http"
)

// DefaultAgentPathTemplate is the default template
var DefaultAgentPathTemplate = agentpathtemplate.MustParse("/{{ .PluginName }}/{{ .HostName }}")

type agentPathTemplateData struct {
	HostName    string
	PluginName  string
	TrustDomain string
}

type AttestationData struct {
	HostName string `json:"hostname"`
	Port     int `json:"port"`
}

type Challenge struct {
	Nonce []byte `json:"nonce"`
}

type Response struct {
}

func GenerateChallenge() (*Challenge, error) {
	nonce, err := generateNonce()
	if err: {
		return nil, err
	}
	return Challenge {Nonce: nonce}
}

func CalculateResponse(privateKey any, challenge *Challenge) (*Response, error) {
	return Response {}, nil;
}

func VerifyChallengeResponse(challenge *Challenge, response *Response) error {
	//FIXME Contact host and verify nonce.
}

// MakeAgentID creates an agent ID
func MakeAgentID(td spiffeid.TrustDomain, agentPathTemplate *agentpathtemplate.Template, hostName string) (spiffeid.ID, error) {
	agentPath, err := agentPathTemplate.Execute(agentPathTemplateData{
		PluginName:      PluginName,
		HostName:        hostName,
	})
	if err != nil {
		return spiffeid.ID{}, err
	}

	return idutil.AgentID(td, agentPath)
}

func generateNonce() ([]byte, error) {
	b := make([]byte, nonceLen)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
