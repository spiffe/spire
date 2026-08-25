package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeServiceConfigJSON(t *testing.T) {
	for _, tt := range []struct {
		name                string
		loadBalancingConfig string
		expect              string
	}{
		{
			name:                "defaults to round robin",
			loadBalancingConfig: "",
			expect:              `{ "loadBalancingConfig": [ { "round_robin": {} } ] }`,
		},
		{
			name:                "uses the configured policies",
			loadBalancingConfig: `[ { "pick_first": {} } ]`,
			expect:              `{ "loadBalancingConfig": [ { "pick_first": {} } ] }`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, MakeServiceConfigJSON(tt.loadBalancingConfig))
		})
	}
}

func TestValidateLoadBalancingConfig(t *testing.T) {
	for _, tt := range []struct {
		name                string
		loadBalancingConfig string
		expectErr           string
	}{
		{
			name:                "empty",
			loadBalancingConfig: "",
		},
		{
			name:                "single policy",
			loadBalancingConfig: `[ { "pick_first": {} } ]`,
		},
		{
			name:                "policy with configuration",
			loadBalancingConfig: `[ { "pick_first": { "shuffleAddressList": true } } ]`,
		},
		{
			name:                "unknown policy followed by a known one",
			loadBalancingConfig: `[ { "not_a_real_policy": {} }, { "round_robin": {} } ]`,
		},
		{
			name:                "not JSON",
			loadBalancingConfig: `pick_first`,
			expectErr:           "must be a JSON array of load balancing policies:",
		},
		{
			name:                "not an array",
			loadBalancingConfig: `{ "pick_first": {} }`,
			expectErr:           "must be a JSON array of load balancing policies:",
		},
		{
			name:                "empty array",
			loadBalancingConfig: `[]`,
			expectErr:           "must contain at least one load balancing policy",
		},
		{
			name:                "policy without a name",
			loadBalancingConfig: `[ {} ]`,
			expectErr:           "each load balancing policy must have exactly one name; got 0",
		},
		{
			name:                "policy with more than one name",
			loadBalancingConfig: `[ { "pick_first": {}, "round_robin": {} } ]`,
			expectErr:           "each load balancing policy must have exactly one name; got 2",
		},
		{
			name:                "no known policy",
			loadBalancingConfig: `[ { "not_a_real_policy": {} } ]`,
			expectErr:           `no supported load balancing policy found in ["not_a_real_policy"]`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLoadBalancingConfig(tt.loadBalancingConfig)
			if tt.expectErr != "" {
				require.ErrorContains(t, err, tt.expectErr)
				return
			}
			require.NoError(t, err)
		})
	}
}
