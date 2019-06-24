# Server plugin: NodeAttestor "gcp_iit"

*Must be used in conjunction with the agent-side gcp_iit plugin*

The `gcp_iit` plugin automatically attests instances using the [GCP Instance Identity Token](https://cloud.google.com/compute/docs/instances/verifying-instance-identity). It also allows an operator to use GCP Instance IDs when defining SPIFFE ID attestation policies.
Agents attested by the gcp_iit attestor will be issued a SPIFFE ID like `spiffe://TRUST_DOMAIN/agent/gcp_iit/PROJECT_ID/INSTANCE_ID`
This plugin requires a whitelist of ProjectID from which nodes can be attested. This also means that you shouldn't run multiple trust domains from the same GCP project.

## Configuration

| Configuration           | Description                                                                                        | Default                                    |
|-------------------------|----------------------------------------------------------------------------------------------------|--------------------------------------------|
| `projectid_whitelist`   | List of whitelisted ProjectIDs from which nodes can be attested.  |         |
| `use_instance_metadata` | If true, instance metadata is fetched from the Google Compute Engine API and used to augment the node selectors produced by the plugin. | false |

A sample configuration:

```
    NodeAttestor "gcp_iit" {
        plugin_data {
            projectid_whitelist = ["project-123"]
        }
    }
```

## Selectors

This plugin generates the following selectors based on information contained in the Instance Identity Token:

| Selector                   | Example                                                      | Description                               |
| -------------------------- | ------------------------------------------------------------ | ----------------------------------------- |
| `gcp_iit:project-id`       | `gcp_iit:project-id:big-kahuna-123456`                       | ID of the project containing the instance |
| `gcp_iit:zone`             | `gcp_iit:zone:us-west1-b`                                    | Zone containing the instance              |
| `gcp_iit:instance-name`    | `gcp_iit:instance-name:blog-server`                          | Name of the instance                      |

If `use_instance_metadata` is true, then the Google Compute Engine API is queried for instance metadata which is used to populate these additional selectors:

| Selector                   | Example                                                      | Description                                                                     |
| -------------------------- | ------------------------------------------------------------ | --------------------------------------------------------------------------------|
| `gcp_iit:tag`              | `gcp_iit:tag:blog-server`                                    | Instance tag (one selector per)
| `gcp_iit:sa`               | `gcp_iit:sa:123456789-compute@developer.gserviceaccount.com` | Service account (one selector per) 

## Authenticating with the Google Compute Engine API

The plugin uses the Application Default Credentials to authenticate with the Google Compute Engine API, as documented by [Setting Up Authentication For Server to Server](https://cloud.google.com/docs/authentication/production).
