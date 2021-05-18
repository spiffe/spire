package fakeupstreamauthority

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	upstreamauthorityv0 "github.com/spiffe/spire/proto/spire/plugin/server/upstreamauthority/v0"
	"github.com/spiffe/spire/test/plugintest"
)

func Load(t *testing.T, config Config) (upstreamauthority.UpstreamAuthority, *UpstreamAuthority) {
	fake := New(t, config)

	server := upstreamauthorityv0.UpstreamAuthorityPluginServer(fake)

	v0 := new(upstreamauthority.V0)
	plugintest.Load(t, catalog.MakeBuiltIn("fake", server), v0)
	return v0, fake
}
