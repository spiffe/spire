package dummybuiltin

import (
	"context"
	"errors"
	"io"

	plugin "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/test/dummy"
)

var (
	// ZeroError is returned by the server when a client sends a 0. It is
	// useful for simulating server failure.
	ZeroError = errors.New("received a zero")
)

type BuiltIn struct {
}

func New() *BuiltIn {
	return &BuiltIn{}
}

func (f *BuiltIn) NoStream(ctx context.Context, req *dummy.NoStreamRequest) (*dummy.NoStreamResponse, error) {
	return &dummy.NoStreamResponse{Value: req.Value}, nil
}

func (f *BuiltIn) ClientStream(stream dummy.ClientStream_PluginStream) error {
	value := int64(0)
recvLoop:
	for {
		req, err := stream.Recv()
		switch {
		case err == io.EOF:
			break recvLoop
		case err != nil:
			return err
		}
		if req.Value == 0 {
			return ZeroError
		}
		value += req.Value
	}

	return stream.SendAndClose(&dummy.ClientStreamResponse{Value: value})
}

func (f *BuiltIn) ServerStream(req *dummy.ServerStreamRequest, stream dummy.ServerStream_PluginStream) error {
	if req.Value == 0 {
		return ZeroError
	}
	for i := int64(0); i < req.Value; i++ {
		if err := stream.Send(&dummy.ServerStreamResponse{Value: i + 1}); err != nil {
			return err
		}
	}
	return nil
}

func (f *BuiltIn) BothStream(stream dummy.BothStream_PluginStream) error {
recvLoop:
	for {
		req, err := stream.Recv()
		switch {
		case err == io.EOF:
			break recvLoop
		case err != nil:
			return err
		}
		if req.Value == 0 {
			return ZeroError
		}
		if err := stream.Send(&dummy.BothStreamResponse{Value: req.Value}); err != nil {
			return err
		}
	}

	return nil
}

func (f *BuiltIn) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return &plugin.ConfigureResponse{
		ErrorList: []string{req.Configuration},
	}, nil
}

func (f *BuiltIn) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{
		Name: "Fake",
	}, nil
}
