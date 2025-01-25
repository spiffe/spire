//go:build !windows

package common

import (
	"os"
)

const (
	// DefaultRunSocketPath is the SPIRE agent's default socket path
	DefaultRunSocketPath = "/tmp/spire-agent/public/api.sock"
	// DefaultAdminSocketPath is the SPIRE agent's default admin socket path
	DefaultAdminSocketPath = "/tmp/spire-agent/private/admin.sock"
)

// DefaultSocketPath is the SPIRE agent's default socket path
var DefaultSocketPath string

func init() {
	DefaultSocketPath = DefaultRunSocketPath
	ses := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	if ses != "" {
		DefaultSocketPath = ses
	}
}
