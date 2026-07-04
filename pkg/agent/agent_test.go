package agent

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckHealthWithWorkloadAPIDisabled(t *testing.T) {
	a := New(&Config{})

	state := a.CheckHealth()
	require.NotNil(t, state.Started)
	require.False(t, *state.Started)
	require.False(t, state.Ready)
	require.True(t, state.Live)
	require.Nil(t, state.ReadyDetails)
	require.Nil(t, state.LiveDetails)

	a.started = true
	state = a.CheckHealth()
	require.NotNil(t, state.Started)
	require.True(t, *state.Started)
	require.True(t, state.Ready)
	require.True(t, state.Live)
	require.Nil(t, state.ReadyDetails)
	require.Nil(t, state.LiveDetails)
}
