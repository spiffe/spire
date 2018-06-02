# Server plugin: NodeAttestor "gcp_instance_identity_token"

*Must be used in conjunction with the agent-side gcp_instance_identity_token plugin*

The `gcp_instance_identity_token` plugin automatically attests instances using the [GCP Instance Identity Token](https://cloud.google.com/compute/docs/instances/verifying-instance-identity). It also allows an operator to use GCP Instance IDs when defining SPIFFE ID attestation policies. 
Agents attested by the gcp_instance_identity_token attestor will be issued a SPIFFE ID like `spiffe://example.org/agent/gcp_instance_identity_token/PROJECT_ID/INSTANCE_ID`

| Configuration           | Description                                                                                        | Default                                    |
|-------------------------|----------------------------------------------------------------------------------------------------|--------------------------------------------|
| trust_domain            | The trust domain that the agent belongs to.                                                        |                                            |
| audience                | Audience parameter used inside the tokens. Needs be equal to the audience parameter in the agent.  |                                            |
| google_cert_url         | URL of the Google certificates used to sign the Identity Token                                     | https://www.googleapis.com/oauth2/v1/certs |
| max_token_lifetime_secs | Maximum token lifetime in seconds for the token to be considered valid. Default: 1 day             | 86400                                      |
| clock_skew_secs         | Leeway during token validity timeframe validation in seconds. Default: 5 minutes                   | 300                                        |