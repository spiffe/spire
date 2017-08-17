package pkg_test

import (
	"testing"

	"github.com/spiffe/sri/control_plane/plugins/upstream_ca"
	"github.com/spiffe/sri/control_plane/plugins/upstream_ca/memory/pkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemory_Configure(t *testing.T) {
	t.SkipNow()
}

func TestMemory_GetPluginInfo(t *testing.T) {
	m := createDefault(t)
	res, err := m.GetPluginInfo()
	require.NoError(t, err)
	assert.NotNil(t, res)
}

func TestMemory_SubmitCSR(t *testing.T) {
	t.SkipNow()
}

func createDefault(t *testing.T) upstreamca.UpstreamCa {
	m, err := pkg.NewWithDefault()
	require.NoError(t, err)
	return m
}
