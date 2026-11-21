package health

import (
	"testing"
	"time"

	logtest "github.com/sirupsen/logrus/hooks/test"
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
		{name: "rejects a zero duration", raw: "0s", expectedErr: "check_interval must be longer than 1s"},
		{name: "rejects the failure retry interval", raw: "1s", expectedErr: "check_interval must be longer than 1s"},
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

func TestValidate(t *testing.T) {
	for _, tt := range []struct {
		name        string
		config      Config
		expectedErr string
	}{
		{
			name:   "listener disabled",
			config: Config{ReadyPath: "ready", LivePath: "ready"},
		},
		{
			name:   "default paths",
			config: Config{ListenerEnabled: true},
		},
		{
			name:   "custom paths",
			config: Config{ListenerEnabled: true, ReadyPath: "/healthz/ready", LivePath: "/healthz/live"},
		},
		{
			name:   "only ready_path set",
			config: Config{ListenerEnabled: true, ReadyPath: "/up"},
		},
		{
			name:        "ready_path without a leading slash",
			config:      Config{ListenerEnabled: true, ReadyPath: "ready"},
			expectedErr: `invalid health_checks ready_path: parsing "ready": at offset 0: host/path missing /`,
		},
		{
			name:        "live_path without a leading slash",
			config:      Config{ListenerEnabled: true, LivePath: "live"},
			expectedErr: `invalid health_checks live_path: parsing "live": at offset 0: host/path missing /`,
		},
		{
			name:        "path with a space",
			config:      Config{ListenerEnabled: true, ReadyPath: "/not ready"},
			expectedErr: `invalid health_checks ready_path: parsing "/not ready": at offset 0: invalid method "/not"`,
		},
		{
			name:        "same paths",
			config:      Config{ListenerEnabled: true, ReadyPath: "/health", LivePath: "/health"},
			expectedErr: `health_checks ready_path and live_path must be different, both are "/health"`,
		},
		{
			name:        "live_path is the default ready_path",
			config:      Config{ListenerEnabled: true, LivePath: "/ready"},
			expectedErr: `health_checks ready_path and live_path must be different, both are "/ready"`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectedErr != "" {
				require.EqualError(t, err, tt.expectedErr)
				return
			}
			require.NoError(t, err)
			// A valid configuration must not make the checker panic.
			if tt.config.ListenerEnabled {
				log, _ := logtest.NewNullLogger()
				require.NotPanics(t, func() { NewChecker(tt.config, log) })
			}
		})
	}
}
