package policy

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
)

// Engine drives policy management.
type Engine struct {
	rego rego.PartialResult
}

type EngineConfig struct {
	FileProvider *FileProviderConfig `hcl:"file_provider"`
}

type FileProviderConfig struct {
	PolicyPath      string `hcl:"policy_path"`
	PermissionsPath string `hcl:"permissions_path"`
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

// NewEngine returns a new policy engine. Or nil if no
// config is provided.
func NewEngine(cfg *EngineConfig) (*Engine, error) {
	if cfg == nil || cfg.FileProvider == nil {
		return nil, nil
	}

	module, err := os.ReadFile(cfg.FileProvider.PolicyPath)
	if err != nil {
		return nil, err
	}
	storefile, err := os.Open(cfg.FileProvider.PermissionsPath)
	if err != nil {
		return nil, err
	}
	defer storefile.Close()
	store := inmem.NewFromReader(storefile)

	return NewEngineFromRego(string(module), store)
}

// DefaultAuthPolicy returns the default policy engine
func DefaultAuthPolicy() (*Engine, error) {
	var json map[string]interface{}
	err := util.UnmarshalJSON([]byte(defaultPermissionData), &json)
	if err != nil {
		return nil, err
	}
	store := inmem.NewFromObject(json)

	return NewEngineFromRego(defaultPolicyRego, store)
}

// NewEngineFromRego is a helper to create the Engine object
func NewEngineFromRego(regoPolicy string, dataStore storage.Store) (*Engine, error) {
	rego := rego.New(
		rego.Query("data.spire.result"),
		rego.Package(`spire`),
		rego.Module("spire.rego", regoPolicy),
		rego.Store(dataStore),
	)
	pr, err := rego.PartialResult(context.Background())
	if err != nil {
		return nil, err
	}

	e := &Engine{
		rego: pr,
	}

	// Test policy with some simple calls to ensure that the
	// policy can be evaluated properly.
	if err = e.testPolicy(); err != nil {
		return nil, err
	}

	return e, nil
}

func (e *Engine) testPolicy() error {
	ctx := context.Background()
	for _, i := range sampleInputs {
		var inp Input
		if err := json.Unmarshal([]byte(i), &inp); err != nil {
			return err
		}

		if _, err := e.Eval(ctx, inp); err != nil {
			return fmt.Errorf("policy is misconfigured: %v", err)
		}
	}
	return nil
}

// Eval determines whether access should be allowed on a resource.
func (e *Engine) Eval(ctx context.Context, input Input) (result Result, err error) {
	rs, err := e.rego.Rego(rego.Input(input)).Eval(ctx)
	if err != nil {
		return result, err
	}

	// TODO(tjulian): figure this out
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return result, errors.New("policy: no matching policies found")
	}

	exp := rs[0].Expressions[0]
	resultMap := exp.Value.(map[string]interface{})

	var ok bool
	result.Allow, ok = resultMap["allow"].(bool)
	if !ok {
		return result, errors.New("policy: result did not contain \"allow\" bool value")
	}

	getBoolValue := func(name string) (bool, error) {
		value, ok := resultMap[name].(bool)
		if !ok {
			return false, fmt.Errorf("policy: result did not contain %q bool value", name)
		}
		return value, nil
	}

	if result.AllowIfAdmin, err = getBoolValue(allowIfAdminKey); err != nil {
		return Result{}, err
	}

	result.AllowIfLocal, ok = resultMap["allow_if_local"].(bool)
	if !ok {
		return result, errors.New("policy: result did not contain \"allow_if_local\" bool value")
	}

	result.AllowIfDownstream, ok = resultMap["allow_if_downstream"].(bool)
	if !ok {
		return result, errors.New("policy: result did not contain \"allow_if_downstream\" bool value")
	}

	result.AllowIfAgent, ok = resultMap["allow_if_agent"].(bool)
	if !ok {
		return result, errors.New("policy: result did not contain \"allow_if_agent\" bool value")
	}

	return result, nil
}
