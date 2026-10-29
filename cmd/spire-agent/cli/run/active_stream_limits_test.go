package run

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/hcl/scanner"
	"github.com/hashicorp/hcl/hcl/token"
	"github.com/spiffe/spire/pkg/agent"
	"github.com/stretchr/testify/require"
)

func parseActiveStreamConfig(t *testing.T, body string) *Config {
	t.Helper()
	parsed, err := ParseFile(writeActiveStreamConfig(t, body), false)
	require.NoError(t, err)
	return parsed
}

func writeActiveStreamConfig(t *testing.T, body string) string {
	t.Helper()
	contents := fmt.Sprintf(`agent {
  data_dir = "."
  log_level = "INFO"
  server_address = "192.168.1.1"
  server_port = 1337
  trust_bundle_path = "../../../../conf/agent/dummy_root_ca.crt"
  trust_bundle_format = "pem"
  trust_domain = "example.org"
  experimental {
    stream_limits {
%s
    }
  }
}
plugins {}`, body)
	path := filepath.Join(t.TempDir(), "agent.conf")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0600))
	return path
}

func TestActiveStreamLimitsConfiguration(t *testing.T) {
	input := parseActiveStreamConfig(t, `fetch_x509_svid = 1
      fetch_x509_bundles = 2
      fetch_jwt_bundles = 3
      stream_secrets = 4
      per_workload = 5
      global = 6
      max_pending = 7`)
	configured, err := NewAgentConfig(input, nil, false)
	require.NoError(t, err, "all seven stream limits must be accepted in the experimental config")
	requireStreamLimitValues(t, configured, map[string]int{
		"FetchX509SVID": 1, "FetchX509Bundles": 2, "FetchJWTBundles": 3, "StreamSecrets": 4, "PerWorkload": 5, "Global": 6, "MaxPending": 7,
	})

	t.Run("explicit_zero", func(t *testing.T) {
		input := parseActiveStreamConfig(t, `fetch_x509_svid = 0
      fetch_x509_bundles = 0
      fetch_jwt_bundles = 0
      stream_secrets = 0
      per_workload = 0
      global = 0
      max_pending = 0`)
		configured, err := NewAgentConfig(input, nil, false)
		require.NoError(t, err, "explicit zero ceilings must be accepted as unlimited")
		requireStreamLimitValues(t, configured, map[string]int{
			"FetchX509SVID": 0, "FetchX509Bundles": 0, "FetchJWTBundles": 0, "StreamSecrets": 0, "PerWorkload": 0, "Global": 0, "MaxPending": 0,
		})
	})

	omitted, err := NewAgentConfig(defaultValidConfig(), nil, false)
	require.NoError(t, err, "omitting stream_limits must preserve existing startup")
	requireStreamLimitValues(t, omitted, map[string]int{
		"FetchX509SVID": 0, "FetchX509Bundles": 0, "FetchJWTBundles": 0, "StreamSecrets": 0, "PerWorkload": 0, "Global": 0, "MaxPending": 0,
	})
}

func TestActiveStreamLimitsNegativeConfiguration(t *testing.T) {
	for _, key := range []string{"fetch_x509_svid", "fetch_x509_bundles", "fetch_jwt_bundles", "stream_secrets", "per_workload", "global", "max_pending"} {
		for _, value := range []int{-1, -2, -97} {
			t.Run(fmt.Sprintf("%s_%d", key, value), func(t *testing.T) {
				input, err := ParseFile(writeActiveStreamConfig(t, fmt.Sprintf("%s = %d", key, value)), false)
				if err == nil {
					_, err = NewAgentConfig(input, nil, false)
				}
				require.Error(t, err)
				require.Contains(t, err.Error(), key, "configuration error should identify the HCL key")
			})
		}
	}
}

func streamLimitSample(t *testing.T) string {
	t.Helper()
	sample, err := os.ReadFile("../../../../conf/agent/agent_full.conf")
	require.NoError(t, err)
	lines := strings.Split(string(sample), "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		for strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			line = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "#"), "//"))
		}
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}

func TestActiveStreamLimitsDocumented(t *testing.T) {
	documentation := streamLimitSample(t)
	block := regexp.MustCompile(`\bstream_limits\s*\{`).FindStringIndex(documentation)
	require.NotNil(t, block, "sample should show a stream_limits block")
	section := documentation[block[0]:]
	lexer := scanner.New([]byte(section))
	depth, end := 0, -1
	for tok := lexer.Scan(); tok.Type != token.EOF; tok = lexer.Scan() {
		switch tok.Type {
		case token.LBRACE:
			depth++
		case token.RBRACE:
			depth--
			if depth == 0 {
				end = tok.Pos.Offset + 1
			}
		}
		if end >= 0 {
			break
		}
	}
	require.Positive(t, end, "sample should close the stream_limits block")
	section = strings.ToLower(section[:end])
	for _, setting := range []string{"fetch_x509_svid", "fetch_x509_bundles", "fetch_jwt_bundles", "stream_secrets", "per_workload", "global", "max_pending"} {
		require.Contains(t, section, setting)
	}
}

func requireStreamLimitValues(t *testing.T, config *agent.Config, values map[string]int) {
	t.Helper()
	policy := reflect.ValueOf(config).Elem().FieldByName("WorkloadAPIStreamLimits")
	require.True(t, policy.IsValid(), "agent configuration must retain stream limits")
	for name, want := range values {
		setting := policy.FieldByName(name)
		require.True(t, setting.IsValid(), "missing stream limit %s", name)
		require.Equal(t, reflect.Int, setting.Kind())
		require.Equal(t, int64(want), setting.Int(), "stream limit %s", name)
	}
}
