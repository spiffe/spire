package client

import (
	"encoding/json"
	"errors"
	"fmt"

	"google.golang.org/grpc/balancer"
)

const defaultLoadBalancingConfig = `[ { "round_robin": {} } ]`

func MakeServiceConfigJSON(loadBalancingConfig string) string {
	if loadBalancingConfig == "" {
		loadBalancingConfig = defaultLoadBalancingConfig
	}
	return fmt.Sprintf(`{ "loadBalancingConfig": %s }`, loadBalancingConfig)
}

func ValidateLoadBalancingConfig(loadBalancingConfig string) error {
	if loadBalancingConfig == "" {
		return nil
	}

	var policies []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(loadBalancingConfig), &policies); err != nil {
		return fmt.Errorf("must be a JSON array of load balancing policies: %w", err)
	}

	if len(policies) == 0 {
		return errors.New("must contain at least one load balancing policy")
	}

	var names []string
	for _, policy := range policies {
		if len(policy) != 1 {
			return fmt.Errorf("each load balancing policy must have exactly one name; got %d", len(policy))
		}
		for name := range policy {
			names = append(names, name)
		}
	}

	for _, name := range names {
		if balancer.Get(name) != nil {
			return nil
		}
	}

	return fmt.Errorf("no supported load balancing policy found in %q", names)
}
