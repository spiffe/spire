package fakeupstreamauthority

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	upstreamauthorityv0 "github.com/spiffe/spire/proto/spire/plugin/server/upstreamauthority/v0"
	"github.com/spiffe/spire/test/spiretest"
)

func Load(t *testing.T, config Config) (upstreamauthority.UpstreamAuthority, *UpstreamAuthority) {
	fake := New(t, config)

	server := upstreamauthorityv0.PluginServer(fake)

	var v0 upstreamauthority.V0
	spiretest.LoadPlugin(t, catalog.MakePlugin("fake", server), &v0)
	return v0, fake
}
