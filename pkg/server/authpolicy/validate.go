package authpolicy

import (
	"context"
	"encoding/json"
	"fmt"
)

// validatePolicy runs a few sample inputs with the policy just to make sure
// it doesn't throw any errors
func (e *Engine) validatePolicy(ctx context.Context) error {
	for _, i := range sampleInputs {
		var inp Input
		if err := json.Unmarshal([]byte(i), &inp); err != nil {
			return err
		}

		if _, err := e.Eval(ctx, inp); err != nil {
			return fmt.Errorf("policy is misconfigured: %w", err)
		}
	}
	return nil
}

// sampleInputs consists of input request strings of SPIRE api calls
var sampleInputs = []string{
	getBundleInput,
	healthCheckInput,
	createJoinTokenInput,
	attestAgentInput,
	batchCreateEntryInput,
	batchCreateEntryInputWithEntryID,
	listEntriesInput,
	createEntriesInputWithCaller,
	listEntriesInputWithCaller,
}

const (
	getBundleInput = `
    {
      "caller": "",
      "full_method": "/spire.api.server.bundle.v1.Bundle/GetBundle",
      "req": {}
    }`

	healthCheckInput = `
    {
      "caller": "",
      "full_method": "/grpc.health.v1.Health/Check",
      "req": {}
    }`

	createJoinTokenInput = `
    {
      "caller": "",
      "full_method": "/spire.api.server.agent.v1.Agent/CreateJoinToken",
      "req": {
        "ttl": 600,
        "agent_id": {
          "trust_domain": "example.org",
          "path": "/host"
        }
      }
    }`

	attestAgentInput = `
    {
      "caller": "",
      "full_method": "/spire.api.server.agent.v1.Agent/AttestAgent",
      "req": null
    }
    `

	batchCreateEntryInput = `
    {
      "caller": "",
      "full_method": "/spire.api.server.entry.v1.Entry/BatchCreateEntry",
      "req": {
        "entries": [
          {
            "spiffe_id": {
              "trust_domain": "example.org",
              "path": "/workload"
            },
            "parent_id": {
              "trust_domain": "example.org",
              "path": "/host"
            },
            "selectors": [
              {
                "type": "unix",
                "value": "uid:     1000"
              }
            ]
          }
        ]
      }
    }`

	batchCreateEntryInputWithEntryID = `
    {
      "caller": "",
      "full_method": "/spire.api.server.entry.v1.Entry/BatchCreateEntry",
      "req": {
        "entries": [
          {
            "id": "entry1",
            "spiffe_id": {
              "trust_domain": "example.org",
              "path": "/workload"
            },
            "parent_id": {
              "trust_domain": "example.org",
              "path": "/host"
            },
            "selectors": [
              {
                "type": "unix",
                "value": "uid:1000"
              }
            ]
          }
        ]
      }
    }`

	listEntriesInput = `
    {
      "caller": "",
      "full_method": "/spire.api.server.entry.v1.Entry/ListEntries",
      "req": {
        "filter": {}
      }
    }`

	createEntriesInputWithCaller = `
    {
      "caller": "spiffe://example.org/someid",
      "full_method": "/spire.api.server.entry.v1.Entry/BatchCreateEntry",
      "req": {
        "entries": [
          {
            "spiffe_id": {
              "trust_domain": "example.org",
              "path": "/workload"
            },
            "parent_id": {
              "trust_domain": "example.org",
              "path": "/host"
            },
            "selectors": [
              {
                "type": "unix",
                "value": "uid:1000"
              }
            ]
          }
        ]
      }
    }
    `

	listEntriesInputWithCaller = `
    {
      "caller": "spiffe://example.org/someid",
      "full_method": "/spire.api.server.entry.v1.Entry/ListEntries",
      "req": {
        "filter": {}
      }
    }`
)
