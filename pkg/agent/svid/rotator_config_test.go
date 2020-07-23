package svid

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewRotator(t *testing.T) {
	r, _ := newRotator(&RotatorConfig{})
	if r.c.Interval == 0 {
		t.Error("svid rotator interval should not be 0")
	}
	if r.c.Clk == nil {
		t.Error("svid rotator clock should not be nil")
	}
	require.False(t, r.c.ExperimentalAPIEnabled)

	r, _ = newRotator(&RotatorConfig{ExperimentalAPIEnabled: true})
	require.True(t, r.c.ExperimentalAPIEnabled)
}
