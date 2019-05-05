package policy

import (
	"context"
	"errors"
	"io/ioutil"
	"os"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
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

// NewEngine returns a new policy engine.
func NewEngine(cfg *EngineConfig) (*Engine, error) {
	if cfg == nil || cfg.FileProvider == nil {
		// TODO: return noop engine if config is nil
		return nil, nil
	}
	module, err := ioutil.ReadFile(cfg.FileProvider.PolicyPath)
	if err != nil {
		return nil, err
	}
	storefile, err := os.Open(cfg.FileProvider.PermissionsPath)
	if err != nil {
		return nil, err
	}
	defer storefile.Close()
	store := inmem.NewFromReader(storefile)

	rego := rego.New(
		rego.Query("data.spire.allow"),
		rego.Package(`spire`),
		rego.Module("spire.rego", string(module)),
		rego.Store(store),
	)
	pr, err := rego.PartialResult(context.Background())
	if err != nil {
		return nil, err
	}
	return &Engine{
		rego: pr,
	}, nil
}

// IsAllowed determins whether access should be allowed on a resource.
func (e *Engine) IsAllowed(ctx context.Context, input Input) (bool, error) {
	rs, err := e.rego.Rego(rego.Input(input)).Eval(ctx)
	if err != nil {
		return false, err
	}

	// TODO(tjulian): figure this out
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return false, errors.New("policy: no matching policies found")
	}
	return rs[0].Expressions[0].Value.(bool), nil
}
