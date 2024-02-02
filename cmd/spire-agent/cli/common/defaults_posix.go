//go:build !windows

package common

const (
	// DefaultSocketPath is the SPIRE agent's default socket path
	DefaultSocketPath = "/tmp/spire-agent/public/api.sock"
	// DefaultAdminSocketPath is the SPIRE agent's default admin socket path
	DefaultAdminSocketPath = "/tmp/spire-agent/private/admin.sock"
)
