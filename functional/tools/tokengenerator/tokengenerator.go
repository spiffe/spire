package main

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/spiffe/spire/proto/api/registration"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	serverAddr = "localhost:8081"
)

func main() {
	ctx := context.Background()

	c, err := newRegistrationClient(serverAddr)
	if err != nil {
		panic(err)
	}

	req := &registration.JoinToken{
		Ttl: int32(^uint32(0) >> 1), // Max Int32
	}
	req, err = c.CreateJoinToken(ctx, req)
	if err != nil {
		panic(err)
	}

	fmt.Print(req.GetToken())
}

func newRegistrationClient(address string) (registration.RegistrationClient, error) {
	// TODO: Pass a bundle in here
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	return registration.NewRegistrationClient(conn), err
}
