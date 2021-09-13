package fakeupstreamauthority

import (
	"testing"

	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/test/plugintest"
)

func Load(t *testing.T, config Config) (upstreamauthority.UpstreamAuthority, *UpstreamAuthority) {
	fake := New(t, config)

	server := upstreamauthorityv1.UpstreamAuthorityPluginServer(fake)

	v1 := new(upstreamauthority.V1)
	plugintest.Load(t, catalog.MakeBuiltIn("fake", server), v1)
	return v1, fake
}
