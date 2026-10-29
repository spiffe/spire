package run

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/stretchr/testify/require"
)

func parseFreshnessHCL(t *testing.T, value string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.conf")
	contents := fmt.Sprintf(`
agent {
    experimental {
        federated_bundle_max_staleness = %q
    }
}
`, value)
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	parsed, err := ParseFile(path, false)
	require.NoError(t, err)
	return parsed
}

func validConfigWithFreshness(t *testing.T, value string) *Config {
	t.Helper()
	parsed := parseFreshnessHCL(t, value)
	input := defaultValidConfig()
	input.Agent.Experimental = parsed.Agent.Experimental
	return input
}

func TestFederatedBundleFreshnessConfiguration(t *testing.T) {
	t.Run("22_known_key_accepts_non_negative_durations_and_rejects_malformed_values", func(t *testing.T) {
		logger, _ := logtest.NewNullLogger()
		for _, value := range []string{"", "0s", "1ns", "37m15s"} {
			parsed := parseFreshnessHCL(t, value)
			require.NoError(t, checkForUnknownConfig(parsed, logger))
			actual, err := NewAgentConfig(validConfigWithFreshness(t, value), []log.Option{}, false)
			require.NoError(t, err)
			require.NotNil(t, actual)
			expected := time.Duration(0)
			if value != "" {
				expected, err = time.ParseDuration(value)
				require.NoError(t, err)
			}
			configured := reflect.ValueOf(actual).Elem().FieldByName("FederatedBundleMaxStaleness")
			require.True(t, configured.IsValid(), "AgentConfig must expose FederatedBundleMaxStaleness")
			require.Equal(t, reflect.TypeFor[time.Duration](), configured.Type())
			require.Equal(t, expected, configured.Interface())
		}

		// Malformed values are rejected according to Go duration parsing rather
		// than by matching one special string.
		for _, value := range []string{"eventually", "1fortnight", "999999999999999999999999h"} {
			input := validConfigWithFreshness(t, value)
			_, err := NewAgentConfig(input, []log.Option{}, false)
			require.Error(t, err)
		}
	})

	t.Run("23_negative_duration_is_rejected", func(t *testing.T) {
		for _, value := range []string{"-1ns", "-2s", "-37m15s"} {
			input := validConfigWithFreshness(t, value)
			_, err := NewAgentConfig(input, []log.Option{}, false)
			require.Error(t, err)
		}
	})
}
