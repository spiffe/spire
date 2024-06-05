package httpchallenge

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/spiffe/spire/pkg/common/idutil"
)

const (
	nonceLen = 32

	// PluginName for http based attestor
	PluginName = "http_challenge"
)

// DefaultAgentPathTemplate is the default template
var DefaultAgentPathTemplate = agentpathtemplate.MustParse("/{{ .PluginName }}/{{ .HostName }}")

type agentPathTemplateData struct {
	HostName    string
	PluginName  string
	TrustDomain string
}

type AttestationData struct {
	HostName  string `json:"hostname"`
	AgentName string `json:"agentname"`
	Port      int    `json:"port"`
}

type Challenge struct {
	Nonce []byte `json:"nonce"`
}

type Response struct {
}

func GenerateChallenge() (*Challenge, error) {
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}
	return &Challenge{Nonce: nonce}, nil
}

func CalculateResponse(_ *Challenge) (*Response, error) {
	return &Response{}, nil
}

func VerifyChallengeResponse(attestationData *AttestationData, challenge *Challenge, _ *Response) error {
	if strings.Contains(attestationData.HostName, "/") {
		return fmt.Errorf("hostname can not contain a slash")
	}
	if strings.Contains(attestationData.HostName, "/") {
		return fmt.Errorf("hostname can not contain a colon")
	}
	if strings.Contains(attestationData.AgentName, ".") {
		return fmt.Errorf("agentname can not contain a dot")
	}
	if strings.Contains(string(challenge.Nonce), ".") {
		return fmt.Errorf("nonce can not contain a dot")
	}
	turl := url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(attestationData.HostName, strconv.Itoa(attestationData.Port)),
		Path:   fmt.Sprintf("/.well-known/spiffe/nodeattestor/http_challenge/%s/%s", attestationData.AgentName, challenge.Nonce),
	}

	resp, err := http.Get(turl.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if bytes.Equal(body, challenge.Nonce) {
		return nil
	}
	return fmt.Errorf("expected nonce %q but got %q", string(challenge.Nonce), string(body))
}

// MakeAgentID creates an agent ID
func MakeAgentID(td spiffeid.TrustDomain, agentPathTemplate *agentpathtemplate.Template, hostName string) (spiffeid.ID, error) {
	agentPath, err := agentPathTemplate.Execute(agentPathTemplateData{
		PluginName: PluginName,
		HostName:   hostName,
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
	retval := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
	base64.StdEncoding.Encode(retval, b)

	return retval, nil
}
