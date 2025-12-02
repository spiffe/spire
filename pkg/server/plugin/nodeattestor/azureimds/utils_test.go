package azureimds

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSelectorValue(t *testing.T) {
	tests := []struct {
		name     string
		parts    []string
		expected string
	}{
		{
			name:     "single part",
			parts:    []string{"part1"},
			expected: "part1",
		},
		{
			name:     "multiple parts",
			parts:    []string{"part1", "part2", "part3"},
			expected: "part1:part2:part3",
		},
		{
			name:     "empty parts",
			parts:    []string{},
			expected: "",
		},
		{
			name:     "parts with empty strings",
			parts:    []string{"part1", "", "part3"},
			expected: "part1::part3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := selectorValue(tt.parts...)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestGetAzureAssertionFunc(t *testing.T) {
	validToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ" // #nosec G101

	tests := []struct {
		name          string
		tokenPath     string
		readerFunc    func(name string) ([]byte, error)
		expectErr     bool
		expectedToken string
		errorContains string
	}{
		{
			name:      "success",
			tokenPath: "/path/to/token",
			readerFunc: func(name string) ([]byte, error) {
				return []byte(validToken), nil
			},
			expectErr:     false,
			expectedToken: validToken,
		},
		{
			name:      "read error",
			tokenPath: "/path/to/token",
			readerFunc: func(name string) ([]byte, error) {
				return nil, errors.New("read failed")
			},
			expectErr:     true,
			errorContains: "unable to read token file",
		},
		{
			name:      "invalid token format",
			tokenPath: "/path/to/token",
			readerFunc: func(name string) ([]byte, error) {
				return []byte("not-a-valid-jwt"), nil
			},
			expectErr:     true,
			errorContains: "unable to parse token file",
		},
		{
			name:      "empty token",
			tokenPath: "/path/to/token",
			readerFunc: func(name string) ([]byte, error) {
				return []byte(""), nil
			},
			expectErr:     true,
			errorContains: "unable to parse token file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertionFunc := getAzureAssertionFunc(tt.tokenPath, tt.readerFunc)
			token, err := assertionFunc(context.Background())

			if tt.expectErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorContains)
				require.Empty(t, token)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedToken, token)
			}
		})
	}
}

func TestLookupTenantID(t *testing.T) {
	// Note: lookupTenantID makes real HTTP requests to Azure's endpoints.
	// Without mocking the HTTP client (which the current function doesn't support),
	// we can only test with invalid domains that will fail.

	t.Run("invalid domain", func(t *testing.T) {
		// Use an invalid domain that will cause the HTTP request to fail
		tenantID, err := lookupTenantID("invalid-domain-that-does-not-exist-12345.local")
		require.Error(t, err)
		require.Empty(t, tenantID)
	})

	// Test parseIssuer separately to validate the issuer parsing logic
	t.Run("parseIssuer validates issuer format", func(t *testing.T) {
		// Valid issuer
		tenantID, err := parseIssuer("https://sts.windows.net/tenant-id-123/")
		require.NoError(t, err)
		require.Equal(t, "tenant-id-123", tenantID)

		// Invalid issuer
		_, err = parseIssuer("not-a-valid-issuer")
		require.Error(t, err)
	})
}

func TestParseNetworkSecurityGroupID(t *testing.T) {
	tests := []struct {
		name                  string
		id                    string
		expectErr             bool
		expectedResourceGroup string
		expectedName          string
	}{
		{
			name:                  "valid id",
			id:                    "/subscriptions/sub-123/resourceGroups/rg-1/providers/Microsoft.Network/networkSecurityGroups/nsg-1",
			expectErr:             false,
			expectedResourceGroup: "rg-1",
			expectedName:          "nsg-1",
		},
		{
			name:      "malformed id",
			id:        "invalid-id",
			expectErr: true,
		},
		{
			name:      "empty id",
			id:        "",
			expectErr: true,
		},
		{
			name:      "partial id",
			id:        "/subscriptions/sub-123/resourceGroups/rg-1",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resourceGroup, name, err := parseNetworkSecurityGroupID(tt.id)

			if tt.expectErr {
				require.Error(t, err)
				require.Empty(t, resourceGroup)
				require.Empty(t, name)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedResourceGroup, resourceGroup)
				require.Equal(t, tt.expectedName, name)
			}
		})
	}
}

func TestParseNetworkInterfaceID(t *testing.T) {
	tests := []struct {
		name                  string
		id                    string
		expectErr             bool
		expectedResourceGroup string
		expectedName          string
	}{
		{
			name:                  "valid id",
			id:                    "/subscriptions/sub-123/resourceGroups/rg-1/providers/Microsoft.Network/networkInterfaces/ni-1",
			expectErr:             false,
			expectedResourceGroup: "rg-1",
			expectedName:          "ni-1",
		},
		{
			name:      "malformed id",
			id:        "invalid-id",
			expectErr: true,
		},
		{
			name:      "empty id",
			id:        "",
			expectErr: true,
		},
		{
			name:      "wrong provider",
			id:        "/subscriptions/sub-123/resourceGroups/rg-1/providers/Microsoft.Compute/networkInterfaces/ni-1",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resourceGroup, name, err := parseNetworkInterfaceID(tt.id)

			if tt.expectErr {
				require.Error(t, err)
				require.Empty(t, resourceGroup)
				require.Empty(t, name)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedResourceGroup, resourceGroup)
				require.Equal(t, tt.expectedName, name)
			}
		})
	}
}

func TestParseVirtualNetworkSubnetID(t *testing.T) {
	tests := []struct {
		name                  string
		id                    string
		expectErr             bool
		expectedResourceGroup string
		expectedNetworkName   string
		expectedSubnetName    string
	}{
		{
			name:                  "valid id",
			id:                    "/subscriptions/sub-123/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/subnet-1",
			expectErr:             false,
			expectedResourceGroup: "rg-1",
			expectedNetworkName:   "vnet-1",
			expectedSubnetName:    "subnet-1",
		},
		{
			name:      "malformed id",
			id:        "invalid-id",
			expectErr: true,
		},
		{
			name:      "empty id",
			id:        "",
			expectErr: true,
		},
		{
			name:      "missing subnet",
			id:        "/subscriptions/sub-123/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resourceGroup, networkName, subnetName, err := parseVirtualNetworkSubnetID(tt.id)

			if tt.expectErr {
				require.Error(t, err)
				require.Empty(t, resourceGroup)
				require.Empty(t, networkName)
				require.Empty(t, subnetName)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedResourceGroup, resourceGroup)
				require.Equal(t, tt.expectedNetworkName, networkName)
				require.Equal(t, tt.expectedSubnetName, subnetName)
			}
		})
	}
}

func TestParseIssuer(t *testing.T) {
	tests := []struct {
		name             string
		issuer           string
		expectErr        bool
		expectedTenantID string
		errorContains    string
	}{
		{
			name:             "valid issuer",
			issuer:           "https://sts.windows.net/tenant-123/",
			expectErr:        false,
			expectedTenantID: "tenant-123",
		},
		{
			name:          "malformed issuer - no trailing slash",
			issuer:        "https://sts.windows.net/tenant-123",
			expectErr:     true,
			errorContains: "malformed tenant ID",
		},
		{
			name:          "malformed issuer - wrong domain",
			issuer:        "https://example.com/tenant-123/",
			expectErr:     true,
			errorContains: "malformed tenant ID",
		},
		{
			name:          "empty issuer",
			issuer:        "",
			expectErr:     true,
			errorContains: "malformed tenant ID",
		},
		{
			name:          "malformed issuer - missing tenant",
			issuer:        "https://sts.windows.net//",
			expectErr:     true,
			errorContains: "malformed tenant ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenantID, err := parseIssuer(tt.issuer)

			if tt.expectErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorContains)
				require.Empty(t, tenantID)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedTenantID, tenantID)
			}
		})
	}
}

func TestGenerateRandomAlphanumeric(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{
			name:   "length 0",
			length: 0,
		},
		{
			name:   "length 1",
			length: 1,
		},
		{
			name:   "length 10",
			length: 10,
		},
		{
			name:   "length 32",
			length: 32,
		},
		{
			name:   "length 100",
			length: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := generateRandomAlphanumeric(tt.length)
			require.NoError(t, err)
			require.Len(t, result, tt.length)

			// Verify all characters are alphanumeric
			for _, char := range result {
				require.True(t,
					(char >= 'a' && char <= 'z') ||
						(char >= 'A' && char <= 'Z') ||
						(char >= '0' && char <= '9'),
					"character %c is not alphanumeric", char)
			}
		})
	}

	// Test randomness - two calls should produce different results (with very high probability)
	t.Run("randomness check", func(t *testing.T) {
		result1, err := generateRandomAlphanumeric(32)
		require.NoError(t, err)
		result2, err := generateRandomAlphanumeric(32)
		require.NoError(t, err)
		require.NotEqual(t, result1, result2)
	})
}

func TestValidateVMSSName(t *testing.T) {
	tests := []struct {
		name          string
		vmssName      string
		expectErr     bool
		errorContains string
	}{
		{
			name:      "valid name - lowercase",
			vmssName:  "myvmss",
			expectErr: false,
		},
		{
			name:      "valid name - uppercase",
			vmssName:  "MYVMSS",
			expectErr: false,
		},
		{
			name:      "valid name - mixed case",
			vmssName:  "MyVmss",
			expectErr: false,
		},
		{
			name:      "valid name - with numbers",
			vmssName:  "vmss123",
			expectErr: false,
		},
		{
			name:      "valid name - with underscore",
			vmssName:  "my_vmss",
			expectErr: false,
		},
		{
			name:      "valid name - ending with underscore",
			vmssName:  "myvmss_",
			expectErr: false,
		},
		{
			name:      "valid name - with hyphen",
			vmssName:  "my-vmss",
			expectErr: false,
		},
		{
			name:      "valid name - with period",
			vmssName:  "my.vmss",
			expectErr: false,
		},
		{
			name:      "valid name - all allowed chars",
			vmssName:  "a1-B2_c3.D4",
			expectErr: false,
		},
		{
			name:      "valid name - max length",
			vmssName:  "a123456789012345678901234567890123456789012345678901234567890123",
			expectErr: false,
		},
		{
			name:          "invalid - empty string",
			vmssName:      "",
			expectErr:     true,
			errorContains: "must be at least 1 character(s) long",
		},
		{
			name:          "invalid - too long",
			vmssName:      "a1234567890123456789012345678901234567890123456789012345678901234",
			expectErr:     true,
			errorContains: "must be at most 64 characters long",
		},
		{
			name:          "invalid - starts with underscore",
			vmssName:      "_vmss",
			expectErr:     true,
			errorContains: "must start with an alphanumeric character",
		},
		{
			name:          "invalid - starts with hyphen",
			vmssName:      "-vmss",
			expectErr:     true,
			errorContains: "must start with an alphanumeric character",
		},
		{
			name:          "invalid - starts with period",
			vmssName:      ".vmss",
			expectErr:     true,
			errorContains: "must start with an alphanumeric character",
		},
		{
			name:          "invalid - ends with hyphen",
			vmssName:      "vmss-",
			expectErr:     true,
			errorContains: "must end with an alphanumeric character or an underscore",
		},
		{
			name:          "invalid - ends with period",
			vmssName:      "vmss.",
			expectErr:     true,
			errorContains: "must end with an alphanumeric character or an underscore",
		},
		{
			name:          "invalid - contains space",
			vmssName:      "my vmss",
			expectErr:     true,
			errorContains: "can only contain alphanumeric characters",
		},
		{
			name:          "invalid - contains special character",
			vmssName:      "vmss@123",
			expectErr:     true,
			errorContains: "can only contain alphanumeric characters",
		},
		{
			name:          "invalid - contains slash",
			vmssName:      "vmss/123",
			expectErr:     true,
			errorContains: "can only contain alphanumeric characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateVMSSName(tt.vmssName)

			if tt.expectErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateUUID(t *testing.T) {
	tests := []struct {
		name          string
		uuid          string
		expectErr     bool
		errorContains string
	}{
		{
			name:      "valid uuid - lowercase",
			uuid:      "550e8400-e29b-41d4-a716-446655440000",
			expectErr: false,
		},
		{
			name:      "valid uuid - uppercase",
			uuid:      "550E8400-E29B-41D4-A716-446655440000",
			expectErr: false,
		},
		{
			name:      "valid uuid - mixed case",
			uuid:      "550e8400-E29b-41D4-a716-446655440000",
			expectErr: false,
		},
		{
			name:      "valid uuid - no hyphens (accepted by uuid library)",
			uuid:      "550e8400e29b41d4a716446655440000",
			expectErr: false,
		},
		{
			name:          "invalid uuid - empty string",
			uuid:          "",
			expectErr:     true,
			errorContains: "invalid UUID format",
		},
		{
			name:          "invalid uuid - wrong format",
			uuid:          "not-a-uuid",
			expectErr:     true,
			errorContains: "invalid UUID format",
		},
		{
			name:          "invalid uuid - too short",
			uuid:          "550e8400-e29b-41d4-a716",
			expectErr:     true,
			errorContains: "invalid UUID format",
		},
		{
			name:          "invalid uuid - invalid characters",
			uuid:          "550e8400-e29b-41d4-a716-44665544000g",
			expectErr:     true,
			errorContains: "invalid UUID format",
		},
		{
			name:          "invalid uuid - wrong separator",
			uuid:          "550e8400_e29b_41d4_a716_446655440000",
			expectErr:     true,
			errorContains: "invalid UUID format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUUID(tt.uuid)

			if tt.expectErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
