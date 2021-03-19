package workloadattestor_test

import (
	"context"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	workloadattestorv0 "github.com/spiffe/spire/proto/spire/agent/workloadattestor/v0"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestV0(t *testing.T) {
	expected := map[int][]*common.Selector{
		1: {},
		2: {{Type: "not", Value: "relevant"}},
	}

	t.Run("attest fails", func(t *testing.T) {
		workloadAttestor := makeFakeV0Plugin(t, expected)
		_, err := workloadAttestor.Attest(context.Background(), 0)
		spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "workloadattestor(test): ohno")
	})

	t.Run("no selectors for pid", func(t *testing.T) {
		workloadAttestor := makeFakeV0Plugin(t, expected)
		actual, err := workloadAttestor.Attest(context.Background(), 1)
		require.NoError(t, err)
		require.Empty(t, actual)
	})

	t.Run("no selectors for pid", func(t *testing.T) {
		workloadAttestor := makeFakeV0Plugin(t, expected)
		actual, err := workloadAttestor.Attest(context.Background(), 2)
		require.NoError(t, err)
		spiretest.RequireProtoListEqual(t, expected[2], actual)
	})
}

func makeFakeV0Plugin(t *testing.T, selectors map[int][]*common.Selector) workloadattestor.WorkloadAttestor {
	fake := &fakePluginV0{selectors: selectors}
	server := workloadattestorv0.PluginServer(fake)

	var plugin workloadattestor.V0
	spiretest.LoadPlugin(t, catalog.MakePlugin("test", server), &plugin)
	return plugin
}

type fakePluginV0 struct {
	workloadattestorv0.UnimplementedWorkloadAttestorServer
	selectors map[int][]*common.Selector
}

func (plugin fakePluginV0) Attest(ctx context.Context, req *workloadattestorv0.AttestRequest) (*workloadattestorv0.AttestResponse, error) {
	selectors, ok := plugin.selectors[int(req.Pid)]
	if !ok {
		// Just return something to test the error wrapping. This is not
		// necessarily an indication of what real plugins should produce.
		return nil, status.Error(codes.InvalidArgument, "ohno")
	}
	return &workloadattestorv0.AttestResponse{
		Selectors: selectors,
	}, nil
}
