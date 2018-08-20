package util

import (
	"context"
	"crypto/tls"
	"log"
	"os"

	"github.com/spiffe/spire/pkg/common/grpcutil"
	"github.com/spiffe/spire/proto/api/registration"

	"google.golang.org/grpc/credentials"
)

const (
	DefaultServerAddr = "localhost:8081"
)

func NewRegistrationClient(ctx context.Context, address string) (registration.RegistrationClient, error) {
	// TODO: Pass a bundle in here
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	credFunc := func() (credentials.TransportCredentials, error) { return credentials.NewTLS(tlsConfig), nil }

	dc := grpcutil.GRPCDialerConfig{
		Log:      log.New(os.Stdout, "", 0),
		CredFunc: credFunc,
	}
	dialer := grpcutil.NewGRPCDialer(dc)

	conn, err := dialer.Dial(ctx, address)
	if err != nil {
		return nil, err
	}
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
