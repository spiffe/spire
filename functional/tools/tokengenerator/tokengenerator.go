package main

import (
	"context"
	"fmt"

	"github.com/spiffe/spire/proto/spire/api/registration"
	"google.golang.org/grpc"
)

const (
	sockPath = "unix:///tmp/spire-registration.sock"
)

func main() {
	ctx := context.Background()

	c, err := newRegistrationClient(sockPath)
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
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	return registration.NewRegistrationClient(conn), err
}
