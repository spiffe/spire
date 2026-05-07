package common

import (
	"os"
	"testing"
)

func TestResolveSocketPath_Spire(t *testing.T) {
	const (
		tplEnv     = "SPIRE_AGENT_PUBLIC_SOCKET_TEMPLATE"
		baseEnv    = "SPIRE_AGENT_PUBLIC_SOCKET"
		defaultP   = "/run/spire/agent/public/api.sock"
		customPath = "/custom/spire.sock"
	)

	tests := []struct {
		name        string
		socketPath  string
		instance    string
		envSetup    map[string]string
		expected    string
		expectError bool
	}{
		{
			name:       "Explicit socket path takes highest priority",
			socketPath: customPath,
			instance:   "agent-1",
			envSetup: map[string]string{
				tplEnv: "/run/spire-%i.sock",
			},
			expected:    customPath,
			expectError: false,
		},
		{
			name:       "Instance resolution using SPIRE template",
			socketPath: defaultP,
			instance:   "prod-node",
			envSetup: map[string]string{
				tplEnv: "/tmp/spire/public-%i.sock",
			},
			expected:    "/tmp/spire/public-prod-node.sock",
			expectError: false,
		},
		{
			name:       "Fallback to SPIRE_AGENT_PUBLIC_SOCKET (no instance)",
			socketPath: defaultP,
			instance:   "",
			envSetup: map[string]string{
				baseEnv: "/var/lib/spire/agent.sock",
			},
			expected:    "/var/lib/spire/agent.sock",
			expectError: false,
		},
		{
			name:        "Return default path when no env or instance provided",
			socketPath:  defaultP,
			instance:    "",
			envSetup:    nil,
			expected:    defaultP,
			expectError: false,
		},
		{
			name:        "Error when instance flag used but template env is empty",
			socketPath:  defaultP,
			instance:    "node-01",
			envSetup:    nil,
			expected:    "",
			expectError: true,
		},
		{
			name:       "Error when template env exists but lacks %i",
			socketPath: defaultP,
			instance:   "node-01",
			envSetup: map[string]string{
				tplEnv: "/run/spire/static-path.sock",
			},
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Clearenv()
			for k, v := range tt.envSetup {
				os.Setenv(k, v)
			}

			got, err := ResolveSocketPath(tt.socketPath, defaultP, tplEnv, tt.instance)

			if (err != nil) != tt.expectError {
				t.Fatalf("ResolveSocketPath() error = %v, expectError %v", err, tt.expectError)
			}

			if got != tt.expected {
				t.Errorf("ResolveSocketPath() got = %q, want %q", got, tt.expected)
			}
		})
	}
}
