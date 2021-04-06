package attestor_test

import (
	"crypto/tls"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func startServer(t *testing.T, tlsConfig *tls.Config) (string, func()) {
	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()
	return listener.Addr().String(), func() {
		server.Stop()
		require.NoError(t, ignoreServerClosed(<-errCh))
	}
}

func ignoreServerClosed(err error) error {
	if err == grpc.ErrServerStopped {
		return nil
	}
	return err
}
