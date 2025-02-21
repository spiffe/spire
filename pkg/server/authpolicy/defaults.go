package authpolicy

import (
	"context"
	_ "embed"

	"github.com/open-policy-agent/opa/storage/inmem" //nolint:staticcheck // Will be removed when https://github.com/spiffe/spire/issues/5887 is closed
	"github.com/open-policy-agent/opa/util"          //nolint:staticcheck // Will be removed when https://github.com/spiffe/spire/issues/5887 is closed
	"github.com/open-policy-agent/opa/v1/ast"
)

var (
	//go:embed policy_data.json
	defaultPolicyData []byte
	//go:embed policy.rego
	defaultPolicyRego string
)

// DefaultAuthPolicy returns the default policy engine
func DefaultAuthPolicy(ctx context.Context) (*Engine, error) {
	var json map[string]any
	if err := util.UnmarshalJSON(defaultPolicyData, &json); err != nil {
		return nil, err
	}
	store := inmem.NewFromObject(json)

	return NewEngineFromRego(ctx, defaultPolicyRego, store, ast.RegoV1)
}
