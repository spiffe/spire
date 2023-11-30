//go:build !windows

package peertracker

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func requireCallerExitFailedDirent(tb testing.TB, actual any) {
	require.Equal(tb, unix.ENOENT, actual)
}
