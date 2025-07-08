package httpchallenge

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/idutil"
)

const (
	nonceLen = 32

	// PluginName for http based attestor
	PluginName = "http_challenge"
)

type AttestationData struct {
	HostName  string `json:"hostname"`
	AgentName string `json:"agentname"`
	Port      int    `json:"port"`
}

type Challenge struct {
	Nonce string `json:"nonce"`
}

type Response struct {
}

func GenerateChallenge(forceNonce string) (*Challenge, error) {
	nonce := forceNonce
	if nonce == "" {
		var err error
		nonce, err = generateNonce()
		if err != nil {
			return nil, err
		}
	}
	return &Challenge{Nonce: nonce}, nil
}

func CalculateResponse(_ *Challenge) (*Response, error) {
	return &Response{}, nil
}

func VerifyChallenge(ctx context.Context, client *http.Client, attestationData *AttestationData, challenge *Challenge) error {
	if attestationData.HostName == "" {
		return errors.New("hostname must be set")
	}
	if attestationData.AgentName == "" {
		return errors.New("agentname must be set")
	}
	if attestationData.Port <= 0 {
		return errors.New("port is invalid")
	}
	if strings.Contains(attestationData.HostName, "/") {
		return errors.New("hostname can not contain a slash")
	}
	if strings.Contains(attestationData.HostName, ":") {
		return errors.New("hostname can not contain a colon")
	}
	if strings.Contains(attestationData.AgentName, ".") {
		return errors.New("agentname can not contain a dot")
	}
	turl := url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(attestationData.HostName, strconv.Itoa(attestationData.Port)),
		Path:   fmt.Sprintf("/.well-known/spiffe/nodeattestor/http_challenge/%s/challenge", attestationData.AgentName),
	}

	req, err := http.NewRequestWithContext(ctx, "GET", turl.String(), nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return err
	}
	nonce := strings.TrimSpace(string(body))
	if nonce != challenge.Nonce {
		return fmt.Errorf("expected nonce %q but got %q", challenge.Nonce, body)
	}
	return nil
}

// MakeAgentID creates an agent ID
func MakeAgentID(td spiffeid.TrustDomain, hostName string) (spiffeid.ID, error) {
	agentPath := fmt.Sprintf("/http_challenge/%s", hostName)

	return idutil.AgentID(td, agentPath)
}

func generateNonce() (string, error) {
	b := make([]byte, nonceLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
