//go:build !windows

package common

import (
	"fmt"
	"net/url"
	"os"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
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
		var err error
		ses, err = workloadapi.TargetFromAddress(ses)
		if err != nil {
			panic(err)
		}
		u, err := url.Parse(ses)
		if u.Scheme != "unix" {
			panic(fmt.Sprintf("Unsupported scheme: %s", u.Scheme))
		}
		DefaultSocketPath = u.Path
	}
}
