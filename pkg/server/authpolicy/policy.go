package authpolicy

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
)

const (
	allowKey             = "allow"
	allowIfAdminKey      = "allow_if_admin"
	allowIfDownstreamKey = "allow_if_downstream"
	allowIfAgentKey      = "allow_if_agent"
	allowIfLocalKey      = "allow_if_local"
)

// Engine drives policy management.
type Engine struct {
	rego rego.PartialResult
}

type OpaEngineConfig struct {
	LocalOpaProvider *LocalOpaProviderConfig `hcl:"local"`
}

type LocalOpaProviderConfig struct {
	RegoPath       string `hcl:"rego_path"`
	PolicyDataPath string `hcl:"policy_data_path"`
}

// Input represents context associated with an access request.
type Input struct {
	// Caller is the authenticated identity of the actor making a request.
	Caller string `json:"caller"`

	// FullMethod is the fully-qualified name of the proto rpc service method.
	FullMethod string `json:"full_method"`

	// Req represents data received from the request body. It MUST be a
	// protobuf request object with fields that are serializable as JSON,
	// since they will be used in policy definitions.
	Req interface{} `json:"req"`
}

type Result struct {
	Allow             bool `json:"allow"`
	AllowIfAdmin      bool `json:"allow_if_admin"`
	AllowIfLocal      bool `json:"allow_if_local"`
	AllowIfDownstream bool `json:"allow_if_downstream"`
	AllowIfAgent      bool `json:"allow_if_agent"`
}

// NewEngineFromConfigOrDefault returns a new policy engine. Or if no
// config is provided, provides the default policy
func NewEngineFromConfigOrDefault(ctx context.Context, cfg *OpaEngineConfig) (*Engine, error) {
	if cfg == nil {
		return DefaultAuthPolicy(ctx)
	}
	return newEngine(ctx, cfg)
}

// newEngine returns a new policy engine. Or nil if no
// config is provided.
func newEngine(ctx context.Context, cfg *OpaEngineConfig) (*Engine, error) {
	switch {
	case cfg == nil:
		return nil, errors.New("policy engine configuration is nil")
	case cfg.LocalOpaProvider == nil:
		return nil, errors.New("policy engine configuration must define a provider")
	}

	module, err := os.ReadFile(cfg.LocalOpaProvider.RegoPath)
	if err != nil {
		return nil, err
	}

	var store storage.Store
	// If permissions file is defined use it, else provide empty store
	if cfg.LocalOpaProvider.PolicyDataPath != "" {
		storefile, err := os.Open(cfg.LocalOpaProvider.PolicyDataPath)
		if err != nil {
			return nil, err
		}
		defer storefile.Close()

		d := util.NewJSONDecoder(storefile)
		var data map[string]interface{}
		if err := d.Decode(&data); err != nil {
			return nil, fmt.Errorf("error decoding JSON databindings: %w", err)
		}
		store = inmem.NewFromObject(data)
	} else {
		store = inmem.NewFromObject(map[string]interface{}{})
	}

	return NewEngineFromRego(ctx, string(module), store)
}

// NewEngineFromRego is a helper to create the Engine object
func NewEngineFromRego(ctx context.Context, regoPolicy string, dataStore storage.Store) (*Engine, error) {
	rego := rego.New(
		rego.Query("data.spire.result"),
		rego.Package("spire"),
		rego.Module("spire.rego", regoPolicy),
		rego.Store(dataStore),
	)
	pr, err := rego.PartialResult(ctx)
	if err != nil {
		return nil, err
	}

	e := &Engine{
		rego: pr,
	}

	// Test policy with some simple calls to ensure that the
	// policy can be evaluated properly.
	if err := e.validatePolicy(ctx); err != nil {
		return nil, fmt.Errorf("authpolicy engine failed to validate on sample test inputs: %w", err)
	}

	return e, nil
}

// Eval determines whether access should be allowed on a resource.
func (e *Engine) Eval(ctx context.Context, input Input) (result Result, err error) {
	rs, err := e.rego.Rego(rego.Input(input)).Eval(ctx)
	if err != nil {
		return Result{}, err
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return Result{}, errors.New("policy: no matching policies found")
	}

	exp := rs[0].Expressions[0]
	resultMap, ok := exp.Value.(map[string]interface{})
	if !ok {
		return Result{}, errors.New("unexpected type in evaluating policy result expression")
	}

	getBoolValue := func(name string) (bool, error) {
		value, ok := resultMap[name].(bool)
		if !ok {
			return false, fmt.Errorf("policy: result did not contain %q bool value", name)
		}
		return value, nil
	}

	if result.Allow, err = getBoolValue(allowKey); err != nil {
		return Result{}, err
	}

	if result.AllowIfAdmin, err = getBoolValue(allowIfAdminKey); err != nil {
		return Result{}, err
	}

	if result.AllowIfLocal, err = getBoolValue(allowIfLocalKey); err != nil {
		return Result{}, err
	}

	if result.AllowIfDownstream, err = getBoolValue(allowIfDownstreamKey); err != nil {
		return Result{}, err
	}

	if result.AllowIfAgent, err = getBoolValue(allowIfAgentKey); err != nil {
		return Result{}, err
	}

	return result, nil
}
