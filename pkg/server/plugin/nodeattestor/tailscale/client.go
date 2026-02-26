package tailscale

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	common "github.com/spiffe/spire/pkg/common/plugin/tailscale"
)

const defaultAPIURL = "https://api.tailscale.com"

// tailscaleClient abstracts the Tailscale API for testability.
type tailscaleClient interface {
	getDeviceByHostname(ctx context.Context, tailnet, hostname string) (*common.DeviceInfo, error)
}

// apiDevice represents a device returned by the Tailscale API.
type apiDevice struct {
	NodeID     string   `json:"nodeId"`
	Hostname   string   `json:"hostname"`
	Name       string   `json:"name"`
	Tags       []string `json:"tags"`
	OS         string   `json:"os"`
	Addresses  []string `json:"addresses"`
	User       string   `json:"user"`
	Authorized bool     `json:"authorized"`
}

// apiDeviceList represents the response from listing devices.
type apiDeviceList struct {
	Devices []apiDevice `json:"devices"`
}

// httpClient implements tailscaleClient using the Tailscale HTTP API.
type httpClient struct {
	apiKey string
	apiURL string
	http   *http.Client
}

func newHTTPClient(apiKey, apiURL string) *httpClient {
	if apiURL == "" {
		apiURL = defaultAPIURL
	}
	return &httpClient{
		apiKey: apiKey,
		apiURL: apiURL,
		http:   http.DefaultClient,
	}
}

func (c *httpClient) getDeviceByHostname(ctx context.Context, tailnet, hostname string) (*common.DeviceInfo, error) {
	url := fmt.Sprintf("%s/api/v2/tailnet/%s/devices", c.apiURL, tailnet)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query Tailscale API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Tailscale API returned status %d: %s", resp.StatusCode, string(body))
	}

	var deviceList apiDeviceList
	if err := json.NewDecoder(resp.Body).Decode(&deviceList); err != nil {
		return nil, fmt.Errorf("failed to decode Tailscale API response: %w", err)
	}

	// The API returns the FQDN in the "name" field (e.g., "machine.tailnet.ts.net").
	// Match against the hostname extracted from the cert SAN.
	for _, d := range deviceList.Devices {
		// Normalize: strip trailing dot if present.
		name := strings.TrimSuffix(d.Name, ".")
		if strings.EqualFold(name, hostname) {
			// Strip "tag:" prefix from tags (Tailscale API returns "tag:foo").
			var tags []string
			for _, t := range d.Tags {
				tags = append(tags, strings.TrimPrefix(t, "tag:"))
			}
			return &common.DeviceInfo{
				NodeID:     d.NodeID,
				Hostname:   d.Hostname,
				Tailnet:    tailnet,
				Tags:       tags,
				OS:         d.OS,
				Addresses:  d.Addresses,
				User:       d.User,
				Authorized: d.Authorized,
			}, nil
		}
	}

	return nil, fmt.Errorf("device with hostname %q not found in tailnet %q", hostname, tailnet)
}
