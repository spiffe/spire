package policy

import (
	_ "embed"
)

var (
	//go:embed permissions.json
	defaultPermissionsData []byte
	//go:embed policy.rego
	defaultPolicyRego string
)

var sampleInputs = []string{
	getBundleInput,
	healthCheckInput,
	createJoinTokenInput,
	attestAgentInput,
	batchCreateEntryInput,
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
