package noderesolver_test

import (
	"context"
	"errors"
	"testing"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/noderesolver"
	"github.com/spiffe/spire/proto/spire/common"
	noderesolverv0 "github.com/spiffe/spire/proto/spire/server/noderesolver/v0"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	expectedSelectors = []*common.Selector{{Type: "TYPE", Value: "VALUE"}}
)

func TestV0(t *testing.T) {
	nr := loadV0Plugin(t)

	t.Run("success with selectors", func(t *testing.T) {
		actualSelectors, err := nr.Resolve(context.Background(), "with-selectors")
		assert.NoError(t, err)
		spiretest.AssertProtoListEqual(t, expectedSelectors, actualSelectors)
	})

	t.Run("success without selectors", func(t *testing.T) {
		actualSelectors, err := nr.Resolve(context.Background(), "without-selectors")
		assert.NoError(t, err)
		assert.Empty(t, actualSelectors)
	})

	t.Run("success with nil map", func(t *testing.T) {
		actualSelectors, err := nr.Resolve(context.Background(), "nil-map")
		assert.NoError(t, err)
		assert.Empty(t, actualSelectors)
	})

	t.Run("success with nil selectors in map", func(t *testing.T) {
		actualSelectors, err := nr.Resolve(context.Background(), "nil-selectors-in-map")
		assert.NoError(t, err)
		assert.Empty(t, actualSelectors)
	})

	t.Run("failure", func(t *testing.T) {
		actualSelectors, err := nr.Resolve(context.Background(), "bad")
		spiretest.AssertGRPCStatus(t, err, codes.FailedPrecondition, "noderesolver(test): ohno")
		assert.Nil(t, actualSelectors)
	})
}

func loadV0Plugin(t *testing.T) noderesolver.NodeResolver {
	server := noderesolverv0.PluginServer(&v0Plugin{})

	var v0 noderesolver.V0
	spiretest.LoadPlugin(t, catalog.MakePlugin("test", server), &v0)
	return v0
}

type v0Plugin struct {
	noderesolverv0.UnimplementedNodeResolverServer
}

func (plugin *v0Plugin) Resolve(ctx context.Context, req *noderesolverv0.ResolveRequest) (*noderesolverv0.ResolveResponse, error) {
	if len(req.BaseSpiffeIdList) != 1 {
		return nil, errors.New("v0 shim did not provide the agent ID")
	}

	resp := &noderesolverv0.ResolveResponse{}
	switch agentID := req.BaseSpiffeIdList[0]; agentID {
	case "with-selectors":
		resp.Map = map[string]*common.Selectors{
			agentID: &common.Selectors{Entries: expectedSelectors},
		}
	case "without-selectors":
		resp.Map = map[string]*common.Selectors{
			agentID: &common.Selectors{},
		}
	case "nil-map":
	case "nil-selectors-in-map":
		resp.Map = map[string]*common.Selectors{
			agentID: nil,
		}
	case "bad":
		return nil, status.Error(codes.FailedPrecondition, "ohno")
	default:
		return nil, errors.New("test setup failure")
	}
	return resp, nil
}
