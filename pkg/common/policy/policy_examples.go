package policy

const defaultPermissionData = `
{
    "apis": [
		{
			"full_method": "/spire.api.server.svid.v1.SVID/MintX509SVID",
			"allow_admin": true,
			"allow_local": true
		},
		{
			"full_method": "/spire.api.server.svid.v1.SVID/MintJWTSVID",
			"allow_admin": true,
			"allow_local": true
		},
		{
			"full_method": "/spire.api.server.svid.v1.SVID/BatchNewX509SVID",
			"allow_agent": true
		},
		{
			"full_method": "/spire.api.server.svid.v1.SVID/NewJWTSVID",
			"allow_agent": true
		},
		{
			"full_method": "/spire.api.server.svid.v1.SVID/NewDownstreamX509CA",
			"allow_downstream": true
		},
		{
			"full_method": "/spire.api.server.bundle.v1.Bundle/GetBundle",
			"allow_any": true
		},
		{
			"full_method": "/spire.api.server.bundle.v1.Bundle/AppendBundle",
			"allow_admin": true,
			"allow_local": true
		},
		{
			"full_method": "/spire.api.server.bundle.v1.Bundle/PublishJWTAuthority",
			"allow_downstream": true
		},
		{
			"full_method": "/spire.api.server.bundle.v1.Bundle/CountBundles",
			"allow_admin": true,
			"allow_local": true
		},
		{
			"full_method": "/spire.api.server.bundle.v1.Bundle/ListFederatedBundles",
			"allow_admin": true,
			"allow_local": true
		},
		{
			"full_method": "/spire.api.server.bundle.v1.Bundle/GetFederatedBundle",
			"allow_admin": true,
			"allow_local": true,
			"allow_agent": true
		},
		{
			"full_method": "/spire.api.server.bundle.v1.Bundle/BatchCreateFederatedBundle",
			"allow_admin": true,
			"allow_local": true
		},
		{
			"full_method": "/spire.api.server.bundle.v1.Bundle/BatchUpdateFederatedBundle",
			"allow_admin": true,
			"allow_local": true
		},
		{
			"full_method": "/spire.api.server.bundle.v1.Bundle/BatchSetFederatedBundle",
			"allow_admin": true,
			"allow_local": true
		},
		{
			"full_method": "/spire.api.server.bundle.v1.Bundle/BatchDeleteFederatedBundle",
			"allow_admin": true,
			"allow_local": true
		},
		{
			"full_method": "/spire.api.server.debug.v1.Debug/GetInfo",
			"allow_local": true
		},
		{
			"full_method": "/spire.api.server.entry.v1.Entry/CountEntries",
			"allow_admin": true,
			"allow_local": true
		},
		{
			"full_method": "/spire.api.server.entry.v1.Entry/ListEntries",
			"allow_admin": true,
			"allow_local": true
		},
		{
			"full_method": "/spire.api.server.entry.v1.Entry/GetEntry",
			"allow_admin": true,
			"allow_local": true
		},
		{
			"full_method": "/spire.api.server.entry.v1.Entry/BatchCreateEntry",
			"allow_admin": true,
			"allow_local": true
		},
		{
			"full_method": "/spire.api.server.entry.v1.Entry/BatchUpdateEntry",
			"allow_admin": true,
			"allow_local": true
		},
		{
			"full_method": "/spire.api.server.entry.v1.Entry/BatchDeleteEntry",
			"allow_admin": true,
			"allow_local": true
		},
		{
			"full_method": "/spire.api.server.entry.v1.Entry/GetAuthorizedEntries",
			"allow_agent": true
		},
		{
			"full_method": "/spire.api.server.agent.v1.Agent/CountAgents",
			"allow_admin": true,
			"allow_local": true
		},
		{
			"full_method": "/spire.api.server.agent.v1.Agent/ListAgents",
			"allow_admin": true,
			"allow_local": true
		},
		{
			"full_method": "/spire.api.server.agent.v1.Agent/GetAgent",
			"allow_admin": true,
			"allow_local": true
		},
		{
			"full_method": "/spire.api.server.agent.v1.Agent/DeleteAgent",
			"allow_admin": true,
			"allow_local": true
		},
		{
			"full_method": "/spire.api.server.agent.v1.Agent/BanAgent",
			"allow_admin": true,
			"allow_local": true
		},
		{
			"full_method": "/spire.api.server.agent.v1.Agent/AttestAgent",
			"allow_any": true
		},
		{
			"full_method": "/spire.api.server.agent.v1.Agent/RenewAgent",
			"allow_agent": true
		},
		{
			"full_method": "/spire.api.server.agent.v1.Agent/CreateJoinToken",
			"allow_admin": true,
			"allow_local": true
		},
		{
			"full_method": "/grpc.health.v1.Health/Check",
			"allow_local": true
		},
		{
			"full_method": "/grpc.health.v1.Health/Watch",
			"allow_local": true
		}
    ]
}
`

const defaultPolicyRego = `
package spire

result = {
  "allow": allow,
  "allow_if_admin": allow_if_admin,
  "allow_if_local": allow_if_local,
  "allow_if_downstream": allow_if_downstream,
  "allow_if_agent": allow_if_agent,

}


### DEFAULT POLICY START ###

default allow_if_admin = false
default allow_if_downstream = false
default allow_if_local = false
default allow_if_agent = false
default allow = false


# Admin allow check
allow_if_admin = true {
    r := data.apis[_]
    r.full_method == input.full_method

    r.allow_admin
}

# Local allow check
allow_if_local = true {
    r := data.apis[_]
    r.full_method == input.full_method

    r.allow_local
}


# Downstream allow check
allow_if_downstream = true {
    r := data.apis[_]
    r.full_method == input.full_method

    r.allow_downstream
}


# Agent allow check
allow_if_agent = true {
    r := data.apis[_]
    r.full_method == input.full_method

    r.allow_agent
}

# Any allow check
allow = true {
    r := data.apis[_]
    r.full_method == input.full_method

    r.allow_any
}

### DEFAULT POLICY ENDSTART  ###
`

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
