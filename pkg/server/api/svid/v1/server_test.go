package svid_test

import (
	"context"
	"testing"

	"github.com/spiffe/spire/pkg/server/api/svid/v1"
	svidpb "github.com/spiffe/spire/proto/spire-next/api/server/svid/v1"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

func TestServer(t *testing.T) {
	registerFn := func(s *grpc.Server) {
		svid.RegisterService(s, FakeService{})
	}

	contextFn := func(ctx context.Context) context.Context {
		return ctx
	}

	conn, done := spiretest.NewAPIServer(t, registerFn, contextFn)
	defer done()

	client := svidpb.NewSVIDClient(conn)

	resp, err := client.MintX509SVID(context.Background(), &svidpb.MintX509SVIDRequest{})
	spiretest.RequireGRPCStatus(t, err, codes.Unimplemented, "not implemented")
	require.Nil(t, resp)
}

type FakeService struct {
	svid.Service
}
