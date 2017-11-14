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
