//go:build windows

package common

const (
	// DefaultNamedPipeName is the SPIRE agent's default named pipe name
	DefaultNamedPipeName = "\\spire-agent\\public\\api"
	// DefaultAdminNamedPipeName is the SPIRE agent's default admin named pipe name
	DefaultAdminSocketPath = "\\spire-agent\\private\\admin"
)
