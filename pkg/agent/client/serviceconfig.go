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

		var name string
		var config json.RawMessage
		for name, config = range policy {
		}
		names = append(names, name)

		// gRPC uses the first registered policy and ignores the rest.
		builder := balancer.Get(name)
		if builder == nil {
			continue
		}
		parser, ok := builder.(balancer.ConfigParser)
		if !ok {
			return nil
		}
		if _, err := parser.ParseConfig(config); err != nil {
			return fmt.Errorf("invalid configuration for load balancing policy %q: %w", name, err)
		}
		return nil
	}

	return fmt.Errorf("no supported load balancing policy found in %q", names)
}
