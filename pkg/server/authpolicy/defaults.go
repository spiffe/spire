package authpolicy

import (
	"context"
	_ "embed"

	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
)

var (
	//go:embed policy_data.json
	defaultPolicyData []byte
	//go:embed policy.rego
	defaultPolicyRego string
)

// DefaultAuthPolicy returns the default policy engine
func DefaultAuthPolicy(ctx context.Context) (*Engine, error) {
	var json map[string]interface{}
	if err := util.UnmarshalJSON(defaultPolicyData, &json); err != nil {
		return nil, err
	}
	store := inmem.NewFromObject(json)

	return NewEngineFromRego(ctx, defaultPolicyRego, store)
}
