package authpolicy_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
	"github.com/spiffe/spire/pkg/server/authpolicy"
	"github.com/stretchr/testify/require"
)

// TestPolicy tests valid policy engines and evaluation of policies using both
// NewEngineFromRego and NewEngineFromConfigOrDefault.
func TestPolicy(t *testing.T) {
	// Make temp directory for testing NewEngineFromConfigOrDefault to load in config
	// from file
	tmpDir, err := os.MkdirTemp("", "spire-test")
	require.Nil(t, err, "failed to create temp directory")
	defer os.RemoveAll(tmpDir) // clean up

	for _, tt := range []struct {
		name         string
		rego         string
		jsonData     string
		input        authpolicy.Input
		expectResult authpolicy.Result
	}{
		{
			name:     "test basic baseline",
			rego:     simpleRego(map[string]bool{}),
			jsonData: "{}",
			input: authpolicy.Input{
				Caller:     "some_caller",
				FullMethod: "some_method",
				Req: map[string]any{
					"some_field": "abc",
				},
			},
			expectResult: authpolicy.Result{
				Allow:             false,
				AllowIfAdmin:      false,
				AllowIfLocal:      false,
				AllowIfDownstream: false,
				AllowIfAgent:      false,
			},
		},
		{
			name: "test basic policy 1",
			rego: simpleRego(map[string]bool{
				"allow": true,
			}),
			jsonData: "{}",
			input: authpolicy.Input{
				Caller:     "some_caller",
				FullMethod: "some_method",
				Req: map[string]any{
					"some_field": "abc",
				},
			},
			expectResult: authpolicy.Result{
				Allow:             true,
				AllowIfAdmin:      false,
				AllowIfLocal:      false,
				AllowIfDownstream: false,
				AllowIfAgent:      false,
			},
		},
		{
			name: "test basic policy 2",
			rego: simpleRego(map[string]bool{
				"allow_if_admin":      true,
				"allow_if_downstream": true,
			}),
			jsonData: "{}",
			input: authpolicy.Input{
				Caller:     "some_caller",
				FullMethod: "some_method",
				Req: map[string]any{
					"some_field": "abc",
				},
			},
			expectResult: authpolicy.Result{
				Allow:             false,
				AllowIfAdmin:      true,
				AllowIfLocal:      false,
				AllowIfDownstream: true,
				AllowIfAgent:      false,
			},
		},
		{
			name:     "test condition policy baseline",
			rego:     condCheckRego("1==2"),
			jsonData: "{}",
			input: authpolicy.Input{
				Caller:     "some_caller",
				FullMethod: "some_method",
				Req: map[string]any{
					"some_field": "abc",
				},
			},
			expectResult: authpolicy.Result{
				Allow:             false,
				AllowIfAdmin:      false,
				AllowIfLocal:      false,
				AllowIfDownstream: false,
				AllowIfAgent:      false,
			},
		},
		{
			name:     "test policy with input caller",
			rego:     condCheckRego("input.caller == \"some_caller\""),
			jsonData: "{}",
			input: authpolicy.Input{
				Caller:     "some_caller",
				FullMethod: "some_method",
				Req: map[string]any{
					"some_field": "abc",
				},
			},
			expectResult: authpolicy.Result{
				Allow:             true,
				AllowIfAdmin:      false,
				AllowIfLocal:      false,
				AllowIfDownstream: false,
				AllowIfAgent:      false,
			},
		},
		{
			name:     "test policy with input full method",
			rego:     condCheckRego("input.full_method == \"some_method\""),
			jsonData: "{}",
			input: authpolicy.Input{
				Caller:     "some_caller",
				FullMethod: "some_method",
				Req: map[string]any{
					"some_field": "abc",
				},
			},
			expectResult: authpolicy.Result{
				Allow:             true,
				AllowIfAdmin:      false,
				AllowIfLocal:      false,
				AllowIfDownstream: false,
				AllowIfAgent:      false,
			},
		},
		{
			name:     "test policy with req field comparison",
			rego:     condCheckRego("input.req.some_field == \"abc\""),
			jsonData: "{}",
			input: authpolicy.Input{
				Caller:     "some_caller",
				FullMethod: "some_method",
				Req: map[string]any{
					"some_field": "abc",
				},
			},
			expectResult: authpolicy.Result{
				Allow:             true,
				AllowIfAdmin:      false,
				AllowIfLocal:      false,
				AllowIfDownstream: false,
				AllowIfAgent:      false,
			},
		},
		{
			name:     "test policy with req nested field comparison",
			rego:     condCheckRego("input.req.nested.field == \"def\""),
			jsonData: "{}",
			input: authpolicy.Input{
				Caller:     "some_caller",
				FullMethod: "some_method",
				Req: map[string]any{
					"some_field": "abc",
					"nested": map[string]any{
						"field": "def",
					},
				},
			},
			expectResult: authpolicy.Result{
				Allow:             true,
				AllowIfAdmin:      false,
				AllowIfLocal:      false,
				AllowIfDownstream: false,
				AllowIfAgent:      false,
			},
		},
		{
			name:     "test policy with data bindings",
			rego:     condCheckRego("input.req.some_field == data.datafield1"),
			jsonData: `{ "datafield1":"data1"}`,
			input: authpolicy.Input{
				Caller:     "some_caller",
				FullMethod: "some_method",
				Req: map[string]any{
					"some_field": "data1",
				},
			},
			expectResult: authpolicy.Result{
				Allow:             true,
				AllowIfAdmin:      false,
				AllowIfLocal:      false,
				AllowIfDownstream: false,
				AllowIfAgent:      false,
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var json map[string]any
			err := util.UnmarshalJSON([]byte(tt.jsonData), &json)
			require.Nil(t, err, "failed to unmarshal data JSON")

			ctxIn := context.Background()
			store := inmem.NewFromObject(json)
			ctx := context.Background()

			// Check with NewEngineFromRego
			pe, err := authpolicy.NewEngineFromRego(ctx, tt.rego, store)
			require.Nil(t, err, "failed to create policy engine")

			res, err := pe.Eval(ctxIn, tt.input)
			require.Nil(t, err, "failed to evaluate")

			require.Equal(t, tt.expectResult, res)

			// Check with NewEngineFromConfigOrDefault
			regoFile := filepath.Join(tmpDir, "rego_file")
			err = os.WriteFile(regoFile, []byte(tt.rego), 0600)
			require.Nil(t, err, "failed to create rego_file")

			permsFile := filepath.Join(tmpDir, "perms_file")
			err = os.WriteFile(permsFile, []byte(tt.jsonData), 0600)
			require.Nil(t, err, "failed to create perms_file")

			ec := authpolicy.OpaEngineConfig{
				LocalOpaProvider: &authpolicy.LocalOpaProviderConfig{
					RegoPath:       regoFile,
					PolicyDataPath: permsFile,
				},
			}
			pe, err = authpolicy.NewEngineFromConfigOrDefault(ctx, &ec)

			require.Nil(t, err, "failed to create policy engine")

			res, err = pe.Eval(ctxIn, tt.input)
			require.Nil(t, err, "failed to evaluate")

			require.Equal(t, tt.expectResult, res)
		})
	}
}

// TestNewEngineFromConfig tests creation of a policy engine from a EngineConfig
// using NewEngineFromConfigOrDefault where the construction of the EngineConfig may not
// be correct, this details the handling of different edge cases in the
// EngineConfig specification.
func TestNewEngineFromConfig(t *testing.T) {
	// Make temp directory for testing NewEngineFromConfigOrDefault to load in config
	// from file
	tmpDir, err := os.MkdirTemp("", "spire-test")
	require.Nil(t, err, "failed to create temp directory")
	defer os.RemoveAll(tmpDir) // clean up

	rego := simpleRego(map[string]bool{})
	jsonData := "{}"

	// Create good policy/perms files
	validRegoFile := filepath.Join(tmpDir, "valid_rego_file")
	err = os.WriteFile(validRegoFile, []byte(rego), 0600)
	require.Nil(t, err, "failed to create valid_rego_file")

	validPermsFile := filepath.Join(tmpDir, "valid_perms_file")
	err = os.WriteFile(validPermsFile, []byte(jsonData), 0600)
	require.Nil(t, err, "failed to create valid_perms_file")

	// Create bad policy/perms files
	invalidRegoFile := filepath.Join(tmpDir, "invalid_rego_file")
	err = os.WriteFile(invalidRegoFile, []byte("invalid rego"), 0600)
	require.Nil(t, err, "failed to create invalid_rego_file")

	invalidPermsFile := filepath.Join(tmpDir, "invalid_perms_file")
	err = os.WriteFile(invalidPermsFile, []byte("{"), 0600)
	require.Nil(t, err, "failed to create invalid_perms_file")

	// Create permissions tmp file
	for _, tt := range []struct {
		name    string
		ec      *authpolicy.OpaEngineConfig
		success bool
	}{
		{
			name: "test valid config",
			ec: &authpolicy.OpaEngineConfig{
				LocalOpaProvider: &authpolicy.LocalOpaProviderConfig{
					RegoPath:       validRegoFile,
					PolicyDataPath: validPermsFile,
				},
			},
			success: true,
		},
		{
			name:    "test default config",
			ec:      nil,
			success: true,
		},
		{
			name: "test valid config without jsonData",
			ec: &authpolicy.OpaEngineConfig{
				LocalOpaProvider: &authpolicy.LocalOpaProviderConfig{
					RegoPath:       validRegoFile,
					PolicyDataPath: "",
				},
			},
			success: true,
		},
		{
			name: "test invalid config with invalid policy file path ",
			ec: &authpolicy.OpaEngineConfig{
				LocalOpaProvider: &authpolicy.LocalOpaProviderConfig{
					RegoPath:       "/invalid/file/path/to/policy",
					PolicyDataPath: validPermsFile,
				},
			},
			success: false,
		},
		{
			name: "test invalid config with invalid perms file path",
			ec: &authpolicy.OpaEngineConfig{
				LocalOpaProvider: &authpolicy.LocalOpaProviderConfig{
					RegoPath:       validRegoFile,
					PolicyDataPath: "/invalid/file/path/to/perms",
				},
			},
			success: false,
		},
		{
			name: "test invalid config with invalid rego file",
			ec: &authpolicy.OpaEngineConfig{
				LocalOpaProvider: &authpolicy.LocalOpaProviderConfig{
					RegoPath:       invalidRegoFile,
					PolicyDataPath: validPermsFile,
				},
			},
			success: false,
		},
		{
			name: "test invalid config with invalid perms file",
			ec: &authpolicy.OpaEngineConfig{
				LocalOpaProvider: &authpolicy.LocalOpaProviderConfig{
					RegoPath:       validRegoFile,
					PolicyDataPath: invalidPermsFile,
				},
			},
			success: false,
		},
		{
			name: "test invalid config without rego",
			ec: &authpolicy.OpaEngineConfig{
				LocalOpaProvider: &authpolicy.LocalOpaProviderConfig{
					RegoPath:       "",
					PolicyDataPath: validPermsFile,
				},
			},
			success: false,
		},
		{
			name: "test invalid config without rego or perms",
			ec: &authpolicy.OpaEngineConfig{
				LocalOpaProvider: &authpolicy.LocalOpaProviderConfig{
					RegoPath:       "",
					PolicyDataPath: "",
				},
			},
			success: false,
		},
		{
			name: "test invalid config without opa_file_provider",
			ec: &authpolicy.OpaEngineConfig{
				LocalOpaProvider: nil,
			},
			success: false,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			_, err := authpolicy.NewEngineFromConfigOrDefault(ctx, tt.ec)
			require.Equal(t, err == nil, tt.success)
		})
	}
}

// TestNewEngineFromRego tests creation of a policy engine with
// NewEngineFromRego
func TestNewEngineFromRego(t *testing.T) {
	for _, tt := range []struct {
		name    string
		rego    string
		success bool
	}{
		{
			name:    "test valid rego",
			rego:    simpleRego(map[string]bool{}),
			success: true,
		},
		{
			name:    "test invalid rego",
			rego:    "invalid rego",
			success: false,
		},
		{
			// We can't test for Eval failure because NewEngine is designed to
			// validate the policy so that it will not fail later on during
			// Eval, so failures of Eval will be purely system exceptions.
			// Instead we test the cases that would fail Eval by testing the
			// creation of the new engine.
			name:    "test validation of SPIRE required fields",
			rego:    badEvalPolicy,
			success: false,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			// Just create arbitrary store since there isn't a way to create
			// a bad store
			store := inmem.New()

			_, err := authpolicy.NewEngineFromRego(ctx, tt.rego, store)
			require.Equal(t, err == nil, tt.success)
		})
	}
}

func condCheckRego(cond string) string {
	regoTemplate := `
    package spire
    result = {
      "allow": allow,
      "allow_if_admin": false,
      "allow_if_local": false,
      "allow_if_downstream": false,
      "allow_if_agent": false
    }
    default allow = false

    allow=true {
        %s
    }
    `
	return fmt.Sprintf(regoTemplate, cond)
}

func simpleRego(m map[string]bool) string {
	regoTemplate := `
    package spire
    result = {
      "allow": %t,
      "allow_if_admin": %t,
      "allow_if_local": %t,
      "allow_if_downstream": %t,
      "allow_if_agent": %t
    }`

	return fmt.Sprintf(regoTemplate, m["allow"], m["allow_if_admin"], m["allow_if_local"], m["allow_if_downstream"], m["allow_if_agent"])
}

var badEvalPolicy = `
    package spire
    result = {
      "allow_if_downstream": false,
      "allow_if_agent": false
    }
    default allow = false

    allow=true {
        %s
    }
    `
