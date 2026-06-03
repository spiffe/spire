//go:build !windows

package util

import (
	"os"
	"strings"
	"testing"
)

func TestGetGRPCAddr(t *testing.T) {
	tests := []struct {
		name          string
		instance      string
		socketPath    string
		envTemplate   string
		envSocket     string
		wantAddr      string
		wantErrString string
	}{
		{
			name:       "Success - Use DefaultSocketPath",
			socketPath: DefaultSocketPath,
			wantAddr:   "unix:" + DefaultSocketPath,
		},
		{
			name:       "Success - Override via custom socketPath",
			socketPath: "/custom/my-spire.sock",
			wantAddr:   "unix:/custom/my-spire.sock",
		},
		{
			name:        "Success - Instance expansion via Template",
			instance:    "prod-1",
			envTemplate: "/tmp/spire-%i.sock",
			socketPath:  DefaultSocketPath,
			wantAddr:    "unix:/tmp/spire-prod-1.sock",
		},
		{
			name:       "Success - Fallback to SPIRE_SERVER_PRIVATE_SOCKET env",
			envSocket:  "/env/var-path.sock",
			socketPath: DefaultSocketPath,
			wantAddr:   "unix:/env/var-path.sock",
		},
		{
			name:          "Error - Instance set but Template missing",
			instance:      "prod-1",
			envTemplate:   "",
			wantErrString: "you must define SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envTemplate != "" {
				t.Setenv("SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE", tt.envTemplate)
			} else {
				os.Unsetenv("SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE")
			}

			if tt.envSocket != "" {
				t.Setenv("SPIRE_SERVER_PRIVATE_SOCKET", tt.envSocket)
			} else {
				os.Unsetenv("SPIRE_SERVER_PRIVATE_SOCKET")
			}

			a := &Adapter{
				adapterOS: adapterOS{
					socketPath: tt.socketPath,
					instance:   tt.instance,
				},
			}

			got, err := a.getGRPCAddr()

			if tt.wantErrString != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErrString)
				}
				if !strings.Contains(err.Error(), tt.wantErrString) {
					t.Errorf("error message %q does not contain %q", err.Error(), tt.wantErrString)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != tt.wantAddr {
				t.Errorf("got address %q, want %q", got, tt.wantAddr)
			}
		})
	}
}
