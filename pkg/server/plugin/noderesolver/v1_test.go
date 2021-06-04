package noderesolver_test

import (
	"context"
	"fmt"
	"testing"

	noderesolverv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/noderesolver/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/noderesolver"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestV1(t *testing.T) {
	nr := loadV1Plugin(t)

	t.Run("success with selectors", func(t *testing.T) {
		actualSelectors, err := nr.Resolve(context.Background(), "with-selectors")
		assert.NoError(t, err)
		spiretest.AssertProtoListEqual(t, []*common.Selector{{Type: "test", Value: "VALUE"}}, actualSelectors)
	})

	t.Run("success without selectors", func(t *testing.T) {
		actualSelectors, err := nr.Resolve(context.Background(), "without-selectors")
		assert.NoError(t, err)
		assert.Empty(t, actualSelectors)
	})

	t.Run("failure", func(t *testing.T) {
		actualSelectors, err := nr.Resolve(context.Background(), "bad")
		spiretest.AssertGRPCStatus(t, err, codes.FailedPrecondition, "noderesolver(test): ohno")
		assert.Nil(t, actualSelectors)
	})
}

func loadV1Plugin(t *testing.T) noderesolver.NodeResolver {
	server := noderesolverv1.NodeResolverPluginServer(&v1Plugin{})

	v1 := new(noderesolver.V1)
	plugintest.Load(t, catalog.MakeBuiltIn("test", server), v1)
	return v1
}

type v1Plugin struct {
	noderesolverv1.UnimplementedNodeResolverServer
}

func (plugin *v1Plugin) Resolve(ctx context.Context, req *noderesolverv1.ResolveRequest) (*noderesolverv1.ResolveResponse, error) {
	resp := &noderesolverv1.ResolveResponse{}
	switch req.AgentId {
	case "with-selectors":
		resp.SelectorValues = []string{"VALUE"}
	case "without-selectors":
	case "bad":
		return nil, status.Error(codes.FailedPrecondition, "ohno")
	default:
		return nil, fmt.Errorf("test setup failure; not agent %q", req.AgentId)
	}
	return resp, nil
}
