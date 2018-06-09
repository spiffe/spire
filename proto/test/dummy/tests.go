package dummy

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNoStream(t *testing.T, dummy Dummy) {
	assert := assert.New(t)

	resp, err := dummy.NoStream(context.Background(), &NoStreamRequest{Value: 1})
	assert.NoError(err)
	assert.Equal(resp.Value, int64(1))
}

func TestClientStream(t *testing.T, dummy Dummy) {
	assert := assert.New(t)

	stream, err := dummy.ClientStream(context.Background())
	assert.NoError(err)
	assert.NoError(stream.Send(&ClientStreamRequest{Value: 1}))
	assert.NoError(stream.Send(&ClientStreamRequest{Value: 2}))
	assert.NoError(stream.Send(&ClientStreamRequest{Value: 3}))
	resp, err := stream.CloseAndRecv()
	assert.NoError(err)
	assert.Equal(resp.Value, int64(6))
}

func TestServerStream(t *testing.T, dummy Dummy) {
	assert := assert.New(t)

	stream, err := dummy.ServerStream(context.Background(), &ServerStreamRequest{Value: 3})
	assert.NoError(err)
	resp, err := stream.Recv()
	assert.NoError(err)
	assert.Equal(resp.Value, int64(1))

	resp, err = stream.Recv()
	assert.NoError(err)
	assert.Equal(resp.Value, int64(2))

	resp, err = stream.Recv()
	assert.NoError(err)
	assert.Equal(resp.Value, int64(3))

	_, err = stream.Recv()
	assert.Equal(err, io.EOF)
}

func TestBothStream(t *testing.T, dummy Dummy) {
	assert := assert.New(t)

	stream, err := dummy.BothStream(context.Background())
	assert.NoError(err)

	assert.NoError(stream.Send(&BothStreamRequest{Value: 1}))
	resp, err := stream.Recv()
	assert.NoError(err)
	assert.Equal(resp.Value, int64(1))

	assert.NoError(stream.Send(&BothStreamRequest{Value: 2}))
	resp, err = stream.Recv()
	assert.NoError(err)
	assert.Equal(resp.Value, int64(2))

	assert.NoError(stream.Send(&BothStreamRequest{Value: 3}))
	resp, err = stream.Recv()
	assert.NoError(err)
	assert.Equal(resp.Value, int64(3))

	assert.NoError(stream.CloseSend())
	_, err = stream.Recv()
	assert.Equal(err, io.EOF)
}
