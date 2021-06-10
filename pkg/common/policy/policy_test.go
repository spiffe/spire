package policy_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
	"github.com/spiffe/spire/pkg/common/policy"
	"github.com/stretchr/testify/require"
)

// TestPolicy tests the policy engine and evaluation of policies
func TestPolicy(t *testing.T) {
	for _, tt := range []struct {
		name         string
		rego         string
		jsonData     string
		input        policy.Input
		expectResult policy.Result
	}{
		{
			name:     "test basic baseline",
			rego:     simpleRego(map[string]bool{}),
			jsonData: "{}",
			input: policy.Input{
				Caller:     "some_caller",
				FullMethod: "some_method",
				Req: map[string]interface{}{
					"some_field": "abc",
				},
			},
			expectResult: policy.Result{
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
			input: policy.Input{
				Caller:     "some_caller",
				FullMethod: "some_method",
				Req: map[string]interface{}{
					"some_field": "abc",
				},
			},
			expectResult: policy.Result{
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
			input: policy.Input{
				Caller:     "some_caller",
				FullMethod: "some_method",
				Req: map[string]interface{}{
					"some_field": "abc",
				},
			},
			expectResult: policy.Result{
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
			input: policy.Input{
				Caller:     "some_caller",
				FullMethod: "some_method",
				Req: map[string]interface{}{
					"some_field": "abc",
				},
			},
			expectResult: policy.Result{
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
			input: policy.Input{
				Caller:     "some_caller",
				FullMethod: "some_method",
				Req: map[string]interface{}{
					"some_field": "abc",
				},
			},
			expectResult: policy.Result{
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
			input: policy.Input{
				Caller:     "some_caller",
				FullMethod: "some_method",
				Req: map[string]interface{}{
					"some_field": "abc",
				},
			},
			expectResult: policy.Result{
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
			input: policy.Input{
				Caller:     "some_caller",
				FullMethod: "some_method",
				Req: map[string]interface{}{
					"some_field": "abc",
				},
			},
			expectResult: policy.Result{
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
			input: policy.Input{
				Caller:     "some_caller",
				FullMethod: "some_method",
				Req: map[string]interface{}{
					"some_field": "abc",
					"nested": map[string]interface{}{
						"field": "def",
					},
				},
			},
			expectResult: policy.Result{
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
			input: policy.Input{
				Caller:     "some_caller",
				FullMethod: "some_method",
				Req: map[string]interface{}{
					"some_field": "data1",
				},
			},
			expectResult: policy.Result{
				Allow:             true,
				AllowIfAdmin:      false,
				AllowIfLocal:      false,
				AllowIfDownstream: false,
				AllowIfAgent:      false,
			},
		},

		/*
		   Test field condition
		   Test nested field conditions
		   Test data JSON
		   Test if all admin thing
		*/
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var json map[string]interface{}
			err := util.UnmarshalJSON([]byte(tt.jsonData), &json)
			require.Nil(t, err, "failed to unmarshal data JSON")

			ctxIn := context.Background()
			store := inmem.NewFromObject(json)
			pe, err := policy.NewEngineFromRego(tt.rego, store)
			require.Nil(t, err, "failed to create policy engine")

			res, err := pe.Eval(ctxIn, tt.input)
			require.Nil(t, err, "failed to evaluate")

			require.Equal(t, tt.expectResult, res)
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
