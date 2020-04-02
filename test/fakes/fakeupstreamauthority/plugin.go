package fakeupstreamauthority

import (
	"context"
	"testing"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/spiretest"
)

func Load(t *testing.T, config Config) (upstreamauthority.UpstreamAuthority, *UpstreamAuthority, func()) {
	fake := New(t, config)

	var ua upstreamauthority.UpstreamAuthority
	uaDone := spiretest.LoadPlugin(t, catalog.MakePlugin("fake",
		upstreamauthority.PluginServer(&upstreamAuthorityPlugin{
			UpstreamAuthority: fake,
		}),
	), &ua)

	return ua, fake, uaDone
}

type upstreamAuthorityPlugin struct {
	*UpstreamAuthority
}

func (m upstreamAuthorityPlugin) Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return &plugin.ConfigureResponse{}, nil
}

func (m upstreamAuthorityPlugin) GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}
