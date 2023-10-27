//go:build windows

package common

const (
	// DefaultNamedPipeName is the SPIRE agent's default named pipe name
	DefaultNamedPipeName = "\\spire-agent\\public\\api"
)
