package run

import (
	"reflect"
	"regexp"
	"testing"

	"github.com/spiffe/spire/pkg/agent"
	"github.com/stretchr/testify/require"
)

func TestActiveStreamLimitsPoolConfiguration(t *testing.T) {
	input := parseActiveStreamConfig(t, `global = 9
 max_pending = 3
 pools = [{ name = "namespace" selectors = ["k8s:ns:shared", "unix:uid:1000"] limit = 2 },
 { name = "all" selectors = [] limit = 0 }]`)
	config, err := NewAgentConfig(input, nil, false)
	require.NoError(t, err)
	policy := reflect.ValueOf(config).Elem().FieldByName("WorkloadAPIStreamLimits")
	require.True(t, policy.IsValid())
	pools := policy.FieldByName("Pools")
	require.True(t, pools.IsValid())
	require.Equal(t, reflect.Slice, pools.Kind())
	require.Equal(t, 2, pools.Len())
	byName := make(map[string]reflect.Value)
	for i := range pools.Len() {
		pool := pools.Index(i)
		byName[pool.FieldByName("Name").String()] = pool
	}
	require.Contains(t, byName, "namespace")
	require.Contains(t, byName, "all")
	require.ElementsMatch(t, []string{"k8s:ns:shared", "unix:uid:1000"}, byName["namespace"].FieldByName("Selectors").Interface())
	require.Equal(t, int64(2), byName["namespace"].FieldByName("Limit").Int())
	require.Zero(t, byName["all"].FieldByName("Limit").Int())
	require.Zero(t, byName["all"].FieldByName("Selectors").Len())
	requireStreamLimitValues(t, config, map[string]int{"Global": 9, "MaxPending": 3})
}

func TestActiveStreamLimitsPoolInvalidConfiguration(t *testing.T) {
	for _, tc := range []struct{ name, key, body string }{
		{"empty_name", "name", `pools = [{name = "" selectors = [] limit = 1}]`},
		{"duplicate_name", "name", `pools = [{name = "x" selectors = [] limit = 1}, {name = "x" selectors = [] limit = 2}]`},
		{"negative_limit", "limit", `pools = [{name = "x" selectors = [] limit = -1}]`},
		{"missing_colon", "selectors", `pools = [{name = "x" selectors = ["k8s"] limit = 1}]`},
		{"empty_type", "selectors", `pools = [{name = "x" selectors = [":ns:shared"] limit = 1}]`},
		{"empty_value", "selectors", `pools = [{name = "x" selectors = ["k8s:"] limit = 1}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := reflect.ValueOf(agent.Config{}).FieldByName("WorkloadAPIStreamLimits")
			require.True(t, policy.IsValid(), "agent must expose stream policy")
			require.True(t, policy.FieldByName("Pools").IsValid(), "agent must expose selector pools")
			input, err := ParseFile(writeActiveStreamConfig(t, tc.body), false)
			if err == nil {
				_, err = NewAgentConfig(input, nil, false)
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.key)
		})
	}
}

func TestActiveStreamLimitsPoolDocumentation(t *testing.T) {
	sample := streamLimitSample(t)
	block := regexp.MustCompile(`(?s)\bpools\s*=\s*\[\s*\{[^}]*}`).FindString(sample)
	require.NotEmpty(t, block, "sample should illustrate a selector pool")
	for _, key := range []string{"selectors", "limit", "name"} {
		require.Regexp(t, `\b`+key+`\s*=`, block)
	}
}
