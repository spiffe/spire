package azureimds

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/gofrs/uuid/v5"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	reNetworkSecurityGroupID = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft.Network/networkSecurityGroups/([^/]+)$`)
	reNetworkInterfaceID     = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft.Network/networkInterfaces/([^/]+)$`)
	reVirtualNetworkSubnetID = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft.Network/virtualNetworks/([^/]+)/subnets/([^/]+)$`)
	reTenantId               = regexp.MustCompile(`^https://sts.windows.net/([^/]+)/$`)
	// VMSS name validation: alphanumeric, underscores, periods, and hyphens
	reVMSSNameAllowedChars = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://login.microsoftonline.com/%s/.well-known/openid-configuration", domain), nil)
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
		return "", fmt.Errorf("malformed tenant ID: %q", issuer)
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

// validateVMSSName validates an Azure VM Scale Set name according to Azure naming rules:
// - Length: Must be between 1 and 64 characters long
// - Allowed Characters: Can contain only alphanumeric characters, underscores, periods, and hyphens
// - Start: Must start with an alphanumeric character
// - End: Must end with an alphanumeric character or an underscore
//
// Note: Uniqueness within the resource group is not validated by this function and must be
// checked separately. Case sensitivity is noted for information but not enforced here.
func validateVMSSName(name string) error {
	const minLength = 1
	const maxLength = 64

	// Check length
	if len(name) < minLength {
		return fmt.Errorf("VMSS name must be at least %d character(s) long, got %d", minLength, len(name))
	}
	if len(name) > maxLength {
		return fmt.Errorf("VMSS name must be at most %d characters long, got %d", maxLength, len(name))
	}

	// Check allowed characters (alphanumeric, underscores, periods, hyphens)
	if !reVMSSNameAllowedChars.MatchString(name) {
		return errors.New("VMSS name can only contain alphanumeric characters, underscores, periods, and hyphens")
	}

	// Check start: must start with alphanumeric
	firstChar := name[0]
	if !((firstChar >= 'a' && firstChar <= 'z') || (firstChar >= 'A' && firstChar <= 'Z') || (firstChar >= '0' && firstChar <= '9')) {
		return errors.New("VMSS name must start with an alphanumeric character")
	}

	// Check end: must end with alphanumeric or underscore
	lastChar := name[len(name)-1]
	if !((lastChar >= 'a' && lastChar <= 'z') || (lastChar >= 'A' && lastChar <= 'Z') || (lastChar >= '0' && lastChar <= '9') || lastChar == '_') {
		return errors.New("VMSS name must end with an alphanumeric character or an underscore")
	}

	return nil
}

// validateUUID validates that a string is a valid UUID using the uuid library.
func validateUUID(s string) error {
	_, err := uuid.FromString(s)
	if err != nil {
		return fmt.Errorf("invalid UUID format: %q: %w", s, err)
	}
	return nil
}
