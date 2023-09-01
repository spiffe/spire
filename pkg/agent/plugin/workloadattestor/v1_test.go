package workloadattestor_test

import (
	"context"
	"testing"

	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestV1(t *testing.T) {
	selectorValues := map[int][]string{
		1: {},
		2: {"someValue"},
	}

	expected := map[int][]*common.Selector{
		1: {},
		2: {{Type: "test", Value: "someValue"}},
	}

	t.Run("attest fails", func(t *testing.T) {
		workloadAttestor := makeFakeV1Plugin(t, selectorValues)
		_, err := workloadAttestor.Attest(context.Background(), 0)
		spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "workloadattestor(test): ohno")
	})

	t.Run("no selectors for pid", func(t *testing.T) {
		workloadAttestor := makeFakeV1Plugin(t, selectorValues)
		actual, err := workloadAttestor.Attest(context.Background(), 1)
		require.NoError(t, err)
		require.Empty(t, actual)
	})

	t.Run("with selectors for pid", func(t *testing.T) {
		workloadAttestor := makeFakeV1Plugin(t, selectorValues)
		actual, err := workloadAttestor.Attest(context.Background(), 2)
		require.NoError(t, err)
		spiretest.RequireProtoListEqual(t, expected[2], actual)
	})
}

func makeFakeV1Plugin(t *testing.T, selectorValues map[int][]string) workloadattestor.WorkloadAttestor {
	fake := &fakePluginV1{selectorValues: selectorValues}
	server := workloadattestorv1.WorkloadAttestorPluginServer(fake)

	plugin := new(workloadattestor.V1)
	plugintest.Load(t, catalog.MakeBuiltIn("test", server), plugin)
	return plugin
}

type fakePluginV1 struct {
	workloadattestorv1.UnimplementedWorkloadAttestorServer
	selectorValues map[int][]string
}

func (plugin fakePluginV1) Attest(_ context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	selectorValues, ok := plugin.selectorValues[int(req.Pid)]
	if !ok {
		// Just return something to test the error wrapping. This is not
		// necessarily an indication of what real plugins should produce.
		return nil, status.Error(codes.InvalidArgument, "ohno")
	}
	return &workloadattestorv1.AttestResponse{
		SelectorValues: selectorValues,
	}, nil
}
