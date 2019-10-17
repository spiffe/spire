package workload

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBackoff(t *testing.T) {
	b := newBackoff()
	b.InitialDelay = time.Second
	b.MaxDelay = 30 * time.Second

	t.Run("test max", func(t *testing.T) {
		for i := 1; i < 30; i++ {
			require.Equal(t, time.Duration(i)*time.Second, b.Duration())
		}
		require.Equal(t, 30*time.Second, b.Duration())
		require.Equal(t, 30*time.Second, b.Duration())
		require.Equal(t, 30*time.Second, b.Duration())
	})

	t.Run("test reset", func(t *testing.T) {
		b.Reset()
		for i := 1; i < 30; i++ {
			require.Equal(t, time.Duration(i)*time.Second, b.Duration())
		}
		require.Equal(t, 30*time.Second, b.Duration())
		require.Equal(t, 30*time.Second, b.Duration())
		require.Equal(t, 30*time.Second, b.Duration())
	})
}
