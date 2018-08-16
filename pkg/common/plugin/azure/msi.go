package azure

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path"

	"github.com/zeebo/errs"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	// DefaultMSIResourceID is the default resource ID to use as the intended
	// audience of the MSI token. The current value is the service ID for the
	// Resource Manager API.
	DefaultMSIResourceID = "https://management.azure.com/"
)

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
	TenantID string `json:"tid,omitempty"`
}

func (c *MSITokenClaims) AgentID(trustDomain string) string {
	u := url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   path.Join("spire", "agent", "azure_msi", c.TenantID, c.Subject),
	}
	return u.String()
}

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type HTTPClientFunc func(*http.Request) (*http.Response, error)

func (fn HTTPClientFunc) Do(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func FetchMSIToken(ctx context.Context, cl HTTPClient, resource string) (string, error) {
	req, err := http.NewRequest("GET", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01", nil)
	if err != nil {
		return "", errs.Wrap(err)
	}
	req.Header.Add("Metadata", "true")

	q := req.URL.Query()
	q.Set("resource", resource)
	req.URL.RawQuery = q.Encode()

	resp, err := cl.Do(req)
	if err != nil {
		return "", errs.Wrap(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errs.New("unexpected status code %d: %s", resp.StatusCode, tryRead(resp.Body))
	}

	r := struct {
		AccessToken string `json:"access_token"`
	}{}

	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", errs.New("unable to decode response: %v", err)
	}

	if r.AccessToken == "" {
		return "", errs.New("response missing access token")
	}

	return r.AccessToken, nil
}

func FetchInstanceMetadata(ctx context.Context, cl HTTPClient) (*InstanceMetadata, error) {
	req, err := http.NewRequest("GET", "http://169.254.169.254/metadata/instance?api-version=2017-08-01&format=json", nil)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	req.Header.Add("Metadata", "true")

	resp, err := cl.Do(req)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errs.New("unexpected status code %d: %s", resp.StatusCode, tryRead(resp.Body))
	}

	metadata := new(InstanceMetadata)
	if err := json.NewDecoder(resp.Body).Decode(metadata); err != nil {
		return nil, errs.New("unable to decode response: %v", err)
	}

	switch {
	case metadata.Compute.Name == "":
		return nil, errs.New("response missing instance name")
	case metadata.Compute.SubscriptionID == "":
		return nil, errs.New("response missing instance subscription id")
	case metadata.Compute.ResourceGroupName == "":
		return nil, errs.New("response missing instance resource group name")
	}

	return metadata, nil
}

func tryRead(r io.Reader) string {
	b := make([]byte, 1024)
	n, _ := r.Read(b)
	return string(b[:n])
}
