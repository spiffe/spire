//go:build windows
// +build windows

package common

const (
	// DefaultNamedPipePath is the SPIRE agent's default named pipe path
	DefaultNamedPipePath = "\\\\.\\pipe\\spire-agent\\public\\api.sock"
)
