package util

import (
	"context"
	"net"

	"github.com/spiffe/spire/proto/spire/api/registration"
	"google.golang.org/grpc"
)

const (
	DefaultSocketPath = "/tmp/spire-registration.sock"
)

func Dial(socketPath string) (*grpc.ClientConn, error) {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	return grpc.Dial(socketPath,
		grpc.WithInsecure(),
		grpc.WithContextDialer(dialer),
		grpc.WithBlock(),
		grpc.FailOnNonTempDialError(true),
		grpc.WithReturnConnectionError())
}

func NewRegistrationClient(socketPath string) (registration.RegistrationClient, error) {
	conn, err := Dial(socketPath)
	if err != nil {
		return nil, err
	}
	return registration.NewRegistrationClient(conn), err
}

func dialer(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", addr)
}

// Pluralizer concatenates `singular` to `msg` when `val` is one, and
// `plural` on all other occasions. It is meant to facilitate friendlier
// CLI output.
func Pluralizer(msg string, singular string, plural string, val int) string {
	result := msg
	if val == 1 {
		result += singular
	} else {
		result += plural
	}

	return result
}
