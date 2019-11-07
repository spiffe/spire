package util

import (
	"net"
	"time"

	"github.com/spiffe/spire/proto/spire/api/registration"
	"google.golang.org/grpc"
)

const (
	DefaultSocketPath = "/tmp/spire-registration.sock"
)

func NewRegistrationClient(socketPath string) (registration.RegistrationClient, error) {
	conn, err := grpc.Dial(socketPath, grpc.WithInsecure(), grpc.WithDialer(dialer)) //nolint: staticcheck
	if err != nil {
		return nil, err
	}
	return registration.NewRegistrationClient(conn), err
}

func dialer(addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", addr, timeout)
}

// Pluralizer concatenates `singular` to `msg` when `val` is one, and
// `plural` on all other occasions. It is meant to facilitate friendlier
// CLI output.
func Pluralizer(msg string, singular string, plural string, val int) string {
	result := msg
	if val == 1 {
		result = result + singular
	} else {
		result = result + plural
	}

	return result
}
