package azureimds

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	reNetworkSecurityGroupID = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft.Network/networkSecurityGroups/([^/]+)$`)
	reNetworkInterfaceID     = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft.Network/networkInterfaces/([^/]+)$`)
	reVirtualNetworkSubnetID = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft.Network/virtualNetworks/([^/]+)/subnets/([^/]+)$`)
	reTenantId               = regexp.MustCompile(`^https://sts.windows.net/([^/]+)/$`)
	// Used to make sure token is valid for credential assertion
	allowedJWTSignatureAlgorithms = []jose.SignatureAlgorithm{
		jose.RS256,
		jose.RS384,
		jose.RS512,
		jose.ES256,
		jose.ES384,
		jose.ES512,
		jose.PS256,
		jose.PS384,
		jose.PS512,
	}
)

func selectorValue(parts ...string) string {
	return strings.Join(parts, ":")
}

func getAzureAssertionFunc(tokenPath string, reader func(name string) ([]byte, error)) func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		token, err := reader(tokenPath)
		if err != nil {
			return "", fmt.Errorf("unable to read token file %q: %w", tokenPath, err)
		}
		if _, err := jwt.ParseSigned(string(token), allowedJWTSignatureAlgorithms); err != nil {
			return "", fmt.Errorf("unable to parse token file %q: %w", tokenPath, err)
		}

		return string(token), nil
	}
}

func lookupTenantID(domain string) (string, error) {
	// make an http request to https://login.microsoftonline.com/<domain>/.well-known/openid-configuration
	req, err := http.NewRequest("GET", fmt.Sprintf("https://login.microsoftonline.com/%s/.well-known/openid-configuration", domain), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request for tenant ID: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch tenant ID: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch tenant ID, status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read tenant ID: %w", err)
	}
	var data struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", fmt.Errorf("failed to unmarshal tenant ID: %w", err)
	}
	return parseIssuer(data.Issuer)
}
func parseNetworkSecurityGroupID(id string) (resourceGroup, name string, err error) {
	m := reNetworkSecurityGroupID.FindStringSubmatch(id)
	if m == nil {
		return "", "", status.Errorf(codes.Internal, "malformed network security group ID %q", id)
	}
	return m[1], m[2], nil
}

func parseNetworkInterfaceID(id string) (resourceGroup, name string, err error) {
	m := reNetworkInterfaceID.FindStringSubmatch(id)
	if m == nil {
		return "", "", status.Errorf(codes.Internal, "malformed network interface ID %q", id)
	}
	return m[1], m[2], nil
}

func parseVirtualNetworkSubnetID(id string) (resourceGroup, networkName, subnetName string, err error) {
	m := reVirtualNetworkSubnetID.FindStringSubmatch(id)
	if m == nil {
		return "", "", "", status.Errorf(codes.Internal, "malformed virtual network subnet ID %q", id)
	}
	return m[1], m[2], m[3], nil
}
func parseIssuer(issuer string) (string, error) {
	m := reTenantId.FindStringSubmatch(issuer)
	if m == nil {
		return "", fmt.Errorf("malformed tenant ID: %s", issuer)
	}
	return m[1], nil
}

func generateRandomAlphanumeric(length int) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	choices := make([]byte, length)
	_, err := rand.Read(choices)
	if err != nil {
		return "", err
	}

	buf := new(bytes.Buffer)
	for _, choice := range choices {
		buf.WriteByte(alphabet[int(choice)%len(alphabet)])
	}
	return buf.String(), nil
}
