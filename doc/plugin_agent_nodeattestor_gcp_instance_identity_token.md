# Server plugin: NodeAttestor "gcp_instance_identity_token"

*Must be used in conjunction with the server-side gcp_instance_identity_token plugin*

The `gcp_instance_identity_token` plugin automatically attests instances using the [GCP Instance Identity Token](https://cloud.google.com/compute/docs/instances/verifying-instance-identity). It also allows an operator to use GCP Instance IDs when defining SPIFFE ID attestation policies. 

| Configuration       | Description                                                                                         | Default                                                                       |
|---------------------|-----------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| trust_domain        | The trust domain that the agent belongs to.                                                         |                                                                               |
| audience            | Audience parameter used inside the tokens. Needs be equal to the audience parameter in the server.  |                                                                               |
| identity_troken_url | Metadata url to retrieve the instance identity token from.                                          | http://metadata/computeMetadata/v1/instance/service-accounts/default/identity |