package util

import (
	"crypto/tls"

	"github.com/spiffe/spire/proto/api/registration"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	DefaultServerAddr = "localhost:8081"
)

func NewRegistrationClient(address string) (registration.RegistrationClient, error) {
	// TODO: Pass a bundle in here
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	return registration.NewRegistrationClient(conn), err
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
