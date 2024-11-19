# Server plugin: NodeAttestor "gcp_iit"

*Must be used in conjunction with the agent-side gcp_iit plugin*

The `gcp_iit` plugin automatically attests instances using the [GCP Instance Identity Token](https://cloud.google.com/compute/docs/instances/verifying-instance-identity). It also allows an operator to use GCP Instance IDs when defining SPIFFE ID attestation policies.
Agents attested by the gcp_iit attestor will be issued a SPIFFE ID like `spiffe://TRUST_DOMAIN/spire/agent/gcp_iit/PROJECT_ID/INSTANCE_ID`
This plugin requires an allow list of ProjectID from which nodes can be attested. This also means that you shouldn't run multiple trust domains from the same GCP project.

## Configuration

| Configuration             | Description                                                                                                                             | Default                                                   |
|---------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------|
| `projectid_allow_list`    | List of ProjectIDs from which nodes can be attested.                                                                                    |                                                           |
| `use_instance_metadata`   | If true, instance metadata is fetched from the Google Compute Engine API and used to augment the node selectors produced by the plugin. | false                                                     |
| `service_account_file`    | Path to the service account file used to authenticate with the Google Compute Engine API                                                |                                                           |
| `allowed_label_keys`      | Instance label keys considered for selectors                                                                                            |                                                           |
| `allowed_metadata_keys`   | Instance metadata keys considered for selectors                                                                                         |                                                           |
| `max_metadata_value_size` | Sets the maximum metadata value size considered by the plugin for selectors                                                             | 128                                                       |
| `agent_path_template`     | A URL path portion format of Agent's SPIFFE ID. Describe in text/template format.                                                       | `"/{{ .PluginName }}/{{ .ProjectID }}/{{ .InstanceID }}"` |

A sample configuration:

```hcl
    NodeAttestor "gcp_iit" {
        plugin_data {
            projectid_allow_list = ["project-123"]
        }
    }
```

## Selectors

This plugin generates the following selectors based on information contained in the Instance Identity Token:

| Selector                | Example                                | Description                               |
|-------------------------|----------------------------------------|-------------------------------------------|
| `gcp_iit:project-id`    | `gcp_iit:project-id:big-kahuna-123456` | ID of the project containing the instance |
| `gcp_iit:zone`          | `gcp_iit:zone:us-west1-b`              | Zone containing the instance              |
| `gcp_iit:instance-name` | `gcp_iit:instance-name:blog-server`    | Name of the instance                      |

If `use_instance_metadata` is true, then the Google Compute Engine API is queried for instance metadata which is used to populate these additional selectors:

| Selector           | Example                                                      | Description                          |
|--------------------|--------------------------------------------------------------|--------------------------------------|
| `gcp_iit:tag`      | `gcp_iit:tag:blog-server`                                    | Instance tag (one selector per)      |
| `gcp_iit:sa`       | `gcp_iit:sa:123456789-compute@developer.gserviceaccount.com` | Service account (one selector per)   |
| `gcp_iit:label`    | `gcp_iit:label:key:value`                                    | Instance label                       |
| `gcp_iit:metadata` | `gcp_iit:metadata:key:value`                                 | Instance metadata (see caveat below) |

Not all instance label and metadata values are useful for node selection. To
prevent the creation of large amounts of useless selectors, labels and metadata
are not used by default. To opt-in to use a specific label or metadata value,
specify the key in the `allowed_label_keys` or `allowed_metadata_keys`
configurable.

Instance metadata can hold large values up to 256KiB. To prevent pushing large amounts
of data into the datastore, a maximum metadata value size limit is enforced. If
an allowed (i.e. key specified in `allowed_metadata_keys`) metadata value is
encountered that exceeds the limit then attestation will fail.

Metadata and label values are optional. If the value isn't present, the
corresponding selector will still have a trailing colon (i.e.
`gcp_iit:label:<key>:`, `gcp_iit:metadata:<key>:`)

## Authenticating with the Google Compute Engine API

The plugin uses the Application Default Credentials to authenticate with the Google Compute Engine API, as documented by [Setting Up Authentication For Server to Server](https://cloud.google.com/docs/authentication/production). When SPIRE Server is running inside GCP, it will use the default service account credentials available to the instance it is running under. When running outside GCP, or if non-default credentials are needed, the path to the service account file containing the credentials may be specified using the `GOOGLE_APPLICATION_CREDENTIALS` environment variable or the `service_account_file` configurable (see Configuration).

The service account must have IAM permissions and Authorization Scopes granting access to the following APIs:

* [compute.instances.get](https://cloud.google.com/compute/docs/reference/rest/v1/instances/get)

## Agent Path Template

The agent path template is a way of customizing the format of generated SPIFFE IDs for agents.
The template formatter is using Golang text/template conventions, it can reference values provided by the plugin or in a [Compute Engine identity token](https://cloud.google.com/compute/docs/instances/verifying-instance-identity#payload).
Details about the template engine are available [here](template_engine.md).

Some useful values are:

| Value                      | Description                                                      |
|----------------------------|------------------------------------------------------------------|
| .PluginName                | The name of the plugin                                           |
| .ProjectID                 | The ID for the project where the instance was created            |
| .InstanceID                | The unique ID for the instance to which this token belongs.      |
| .ProjectNumber             | The unique number for the project where you created the instance |
| .Zone                      | The zone where the instance is located                           |
| .InstanceCreationTimestamp | A Unix timestamp indicating when you created the instance.       |

## Security Considerations

The Instance Identity Token, which this attestor leverages to prove node identity, is available to any process running on the node by default. As a result, it is possible for non-agent code running on a node to attest to the SPIRE Server, allowing it to obtain any workload identity that the node is authorized to run.

While many operators choose to configure their systems to block access to the Instance Identity Token, the SPIRE project cannot guarantee this posture. To mitigate the associated risk, the `gcp_iit` node attestor implements Trust On First Use (or TOFU) semantics. For any given node, attestation may occur only once. Subsequent attestation attempts will be rejected.

It is still possible for non-agent code to complete node attestation before SPIRE Agent can, however this condition is easily and quickly detectable as SPIRE Agent will fail to start, and both SPIRE Agent and SPIRE Server will log the occurrence. Such cases should be investigated as possible security incidents.
