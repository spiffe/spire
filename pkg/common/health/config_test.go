package health

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseCheckInterval(t *testing.T) {
	for _, tt := range []struct {
		name        string
		raw         string
		expected    time.Duration
		expectedErr string
	}{
		{name: "defaults to one minute", expected: time.Minute},
		{name: "parses a duration", raw: "30s", expected: 30 * time.Second},
		{name: "rejects an invalid duration", raw: "b", expectedErr: `could not parse check_interval: time: invalid duration "b"`},
		{name: "rejects a zero duration", raw: "0s", expectedErr: "check_interval must be greater than zero"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := Config{RawCheckInterval: tt.raw}
			err := c.ParseCheckInterval()
			if tt.expectedErr != "" {
				require.EqualError(t, err, tt.expectedErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expected, c.CheckInterval)
		})
	}
}
