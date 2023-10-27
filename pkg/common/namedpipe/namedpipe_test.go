//go:build windows

package namedpipe_test

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/namedpipe"
	"github.com/stretchr/testify/require"
)

func TestGetNamedPipeAddr(t *testing.T) {
	addr := namedpipe.AddrFromName("my-pipe")
	require.Equal(t, "pipe", addr.Network())
	require.Equal(t, "\\\\.\\pipe\\my-pipe", addr.String())
}

func TestGetPipeName(t *testing.T) {
	addr := namedpipe.GetPipeName("\\\\.\\pipe\\my-pipe")
	require.Equal(t, "\\my-pipe", addr)
}
