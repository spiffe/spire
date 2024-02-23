//go:build windows

package common

const (
	// DefaultNamedPipeName is the SPIRE agent's default named pipe name
	DefaultNamedPipeName = "\\spire-agent\\public\\api"
	// DefaultAdminNamedPipeName is the SPIRE agent's default admin named pipe name
	DefaultAdminNamedPipeName = "\\spire-agent\\private\\admin"
)
