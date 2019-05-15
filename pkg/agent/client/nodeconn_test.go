package client

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewNodeConn(t *testing.T) {
	conn := newTestConn(t)
	nodeConn := newNodeConn(conn)
	require.Equal(t, 1, int(nodeConn.refcount))

	nodeConn.Release()
	require.Equal(t, 0, int(nodeConn.refcount))

	// should error since we already closed
	err := conn.Close()
	require.Equal(t, codes.Canceled, status.Code(err))
}

func newTestConn(t *testing.T) *grpc.ClientConn {
	client := New(&Config{
		Log:           log,
		KeysAndBundle: keysAndBundle,
	})
	conn, err := client.dial(context.Background())
	require.NoError(t, err)
	return conn
}

func TestNewNodeAddRelease(t *testing.T) {
	conn := newTestConn(t)
	nodeConn := newNodeConn(conn)
	nodeConn.AddRef()
	nodeConn.Release()
	require.NotNil(t, nodeConn.Conn())
	nodeConn.Release()
	require.Nil(t, nodeConn.Conn())
	nodeConn.Release()
	require.Nil(t, nodeConn.Conn())
}

func TestNewNodeMany(t *testing.T) {
	conn := newTestConn(t)
	nodeConn := newNodeConn(conn)

	waitForAdds := make(chan struct{})
	waitForReleases := make(chan struct{})

	firstRelease := false

	go func() {
		for i := 0; i < 100; i++ {
			nodeConn.AddRef()
			if !firstRelease {
				nodeConn.Release()
				firstRelease = true
			}
		}
		close(waitForAdds)
	}()

	go func() {
		for i := 0; i < 100; i++ {
			nodeConn.Release()
		}
		close(waitForReleases)
	}()

	<-waitForAdds
	<-waitForReleases

	// should error since we already closed
	err := conn.Close()
	require.Equal(t, codes.Canceled, status.Code(err))
}
