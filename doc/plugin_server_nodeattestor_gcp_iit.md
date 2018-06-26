# Server plugin: NodeAttestor "gcp_iit"

*Must be used in conjunction with the agent-side gcp_iit plugin*

The `gcp_iit` plugin automatically attests instances using the [GCP Instance Identity Token](https://cloud.google.com/compute/docs/instances/verifying-instance-identity). It also allows an operator to use GCP Instance IDs when defining SPIFFE ID attestation policies. 
Agents attested by the gcp_iit attestor will be issued a SPIFFE ID like `spiffe://TRUST_DOMAIN/agent/gcp_iit/PROJECT_ID/INSTANCE_ID`
This plugin requires a whitelist of ProjectID from which nodes can be attested. This also means that you shouldn't run multiple trust domains from the same GCP project. 

| Configuration           | Description                                                                                        | Default                                    |
|-------------------------|----------------------------------------------------------------------------------------------------|--------------------------------------------|
| trust_domain            | The trust domain that the agent belongs to.                                                        |                                            |
| projectid_whitelist     | List of whitelisted ProjectIDs from which nodes can be attested.  |         |
