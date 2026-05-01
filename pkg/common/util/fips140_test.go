package util

import (
	"os"
	"testing"
)

func TestFIPS140Only(t *testing.T) {
	tests := []struct {
		name        string
		envValue    string
		mockEnabled bool
		expected    bool
	}{
		{
			name:        "FIPS140 not enabled, no GODEBUG",
			envValue:    "",
			mockEnabled: false,
			expected:    false,
		},
		{
			name:        "FIPS140 enabled, GODEBUG without fips140",
			envValue:    "other=value",
			mockEnabled: true,
			expected:    false,
		},
		{
			name:        "FIPS140 enabled, GODEBUG with fips140=on",
			envValue:    "fips140=on,other=value",
			mockEnabled: true,
			expected:    false,
		},
		{
			name:        "FIPS140 enabled, GODEBUG with fips140=only",
			envValue:    "fips140=only",
			mockEnabled: true,
			expected:    true,
		},
		{
			name:        "FIPS140 enabled, GODEBUG with multiple values including fips140=only",
			envValue:    "other=value,fips140=only,another=setting",
			mockEnabled: true,
			expected:    true,
		},
	}

	originalGodebug := os.Getenv("GODEBUG")
	defer os.Setenv("GODEBUG", originalGodebug)

	originalFipsEnabled := fips140Enabled
	defer func() { fips140Enabled = originalFipsEnabled }()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("GODEBUG", tt.envValue)

			fips140Enabled = func() bool { return tt.mockEnabled }

			if got := FIPS140Only(); got != tt.expected {
				t.Errorf("FIPS140Only() = %v, want %v", got, tt.expected)
			}
		})
	}
}
