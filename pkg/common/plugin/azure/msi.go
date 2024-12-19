package azure

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/spiffe/spire/pkg/common/idutil"
)

const (
	// DefaultMSIResourceID is the default resource ID to use as the intended
	// audience of the MSI token. The current value is the service ID for the
	// Resource Manager API.
	DefaultMSIResourceID = "https://management.azure.com/"
	PluginName           = "azure_msi"
)

// DefaultAgentPathTemplate is the default text/template
var DefaultAgentPathTemplate = agentpathtemplate.MustParse("/{{ .PluginName }}/{{ .TenantID }}/{{ .PrincipalID }}")

type ComputeMetadata struct {
	Name              string `json:"name"`
	SubscriptionID    string `json:"subscriptionId"`
	ResourceGroupName string `json:"resourceGroupName"`
}

type InstanceMetadata struct {
	Compute ComputeMetadata `json:"compute"`
}

type MSIAttestationData struct {
	Token string `json:"token"`
}

type MSITokenClaims struct {
	jwt.Claims
	TenantID    string `json:"tid,omitempty"`
	PrincipalID string `json:"sub,omitempty"`
}

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type HTTPClientFunc func(*http.Request) (*http.Response, error)

func (fn HTTPClientFunc) Do(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func FetchMSIToken(cl HTTPClient, resource string) (string, error) {
	req, err := http.NewRequest("GET", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01", nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Metadata", "true")

	q := req.URL.Query()
	q.Set("resource", resource)
	req.URL.RawQuery = q.Encode()

	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, tryRead(resp.Body))
	}

	r := struct {
		AccessToken string `json:"access_token"`
	}{}

	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", fmt.Errorf("unable to decode response: %w", err)
	}

	if r.AccessToken == "" {
		return "", fmt.Errorf("response missing access token")
	}

	return r.AccessToken, nil
}

func FetchInstanceMetadata(cl HTTPClient) (*InstanceMetadata, error) {
	req, err := http.NewRequest("GET", "http://169.254.169.254/metadata/instance?api-version=2017-08-01&format=json", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Metadata", "true")

	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, tryRead(resp.Body))
	}

	metadata := new(InstanceMetadata)
	if err := json.NewDecoder(resp.Body).Decode(metadata); err != nil {
		return nil, fmt.Errorf("unable to decode response: %w", err)
	}

	switch {
	case metadata.Compute.Name == "":
		return nil, errors.New("response missing instance name")
	case metadata.Compute.SubscriptionID == "":
		return nil, errors.New("response missing instance subscription id")
	case metadata.Compute.ResourceGroupName == "":
		return nil, errors.New("response missing instance resource group name")
	}

	return metadata, nil
}

type agentPathTemplateData struct {
	MSITokenClaims
	PluginName string
}

func MakeAgentID(td spiffeid.TrustDomain, agentPathTemplate *agentpathtemplate.Template, claims *MSITokenClaims) (spiffeid.ID, error) {
	agentPath, err := agentPathTemplate.Execute(agentPathTemplateData{
		MSITokenClaims: *claims,
		PluginName:     PluginName,
	})
	if err != nil {
		return spiffeid.ID{}, err
	}

	return idutil.AgentID(td, agentPath)
}

func tryRead(r io.Reader) string {
	b := make([]byte, 1024)
	n, _ := r.Read(b)
	return string(b[:n])
}
