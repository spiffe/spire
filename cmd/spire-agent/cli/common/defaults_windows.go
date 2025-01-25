//go:build windows

package common

import (
	"os"
)

const (
	// DefaultRunNamedPipeName is the SPIRE agent's default named pipe name
	DefaultRunNamedPipeName = "\\spire-agent\\public\\api"
	// DefaultAdminNamedPipeName is the SPIRE agent's default admin named pipe name
	DefaultAdminNamedPipeName = "\\spire-agent\\private\\admin"
)

// DefaultNamedPipeName is the SPIRE agent's default named pipe name
var DefaultNamedPipeName string

func init() {
	DefaultNamedPipeName = DefaultRunNamedPipeName
	ses := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	if ses != "" {
		DefaultNamedPipeName = ses
	}
}
