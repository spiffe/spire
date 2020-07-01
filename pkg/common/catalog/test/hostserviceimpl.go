package test

import (
	"context"
	"fmt"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/private/test/catalogtest"
)

func NewHostService() catalogtest.HostService {
	return &testHostService{}
}

type testHostService struct{}

func (*testHostService) CallHostService(ctx context.Context, req *catalogtest.Request) (*catalogtest.Response, error) {
	pluginName, ok := catalog.PluginNameFromHostServiceContext(ctx)
	if !ok {
		pluginName = "<unknown>"
	}
	return &catalogtest.Response{
		Out: fmt.Sprintf("hostservice[plugin=%s](%s)", pluginName, req.In),
	}, nil
}
