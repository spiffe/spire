# Akeyless KMS plugin for Spire

[Akeyless](https://www.akeyless.io/) plugin for the [Spire server](https://github.com/spiffe/spire) allows you to manage encryption keys and perform sign operations. Plugin based on [template](https://github.com/spiffe/spire-plugin-sdk/blob/main/templates/server/keymanager) as required by [Spiffe/Spire SDK](https://github.com/spiffe/spire-plugin-sdk#spire-plugin-sdk) and similar to [AWS KMS Plugin](https://github.com/spiffe/spire/tree/main/pkg/server/plugin/keymanager/awskms)


SPIRE supports a rich plugin system. Plugins can either be built in, or external, to SPIRE. External plugins are separate processes. Akeyless SecretsManager plugin is an external plugin. SPIRE communicates with plugins over gRPC.

The plugin binary must then be installed on the same machines running the SPIRE Agent or Server and have sufficient permissions to be executed by the same user that the SPIRE Agent or Server is running as.

Once this has been done, configuration of a third party plugin is done through adding a stanza to the Server or Agent configuration file. Configuration block should include a plugin_cmd stanza that specifies the path to the plugin binary on disk.

```
KeyManager "akeyless_kms" {
	plugin_cmd = "/path/to/plugin_cmd"
	plugin_checksum = "sha256 of the plugin binary"
	plugin_data {
		akeyless_access_key_id = "XXXXXXX"
	}
}
```

## Supported Key Types

The plugin supports all the key types supported by SPIRE: `rsa-2048`, `rsa-4096`, `ec-p256`, and `ec-p384`.


Pluging supports following types of authentications:
* Access Key
* AWS IAM
* Azure
* GCP
* K8S

## Configuration
The plugin accepts the following configuration options:

| Key               | Type   | Required                              | Description                                                                   | Default                                                 |
|-------------------|--------|---------------------------------------|-------------------------------------------------------------------------------|---------------------------------------------------------|
| akeyless_access_key_id     | string | yes | The Access Key Id used to authenticate to Akeyless                                 | Value of the `AKEYLESS_ACCESS_ID` environment variable     |
| akeyless_access_key | string | yes (only if used `AccessKey` authentication type) | The Secret Access Key used to authenticate to Akeyless                             | Value of the `AKEYLESS_ACCESS_KEY` or `CREDENTIALS` environment variables |
| akeyless_gateway_url | string | no                                   | Address of running gateway for communicating using API V2 interface | Value of `AKEYLESS_GATEWAY_URL` environment variable or `http://localhost:8080/v2` if not provided                                                      |
| akeyless_azure_object_id            | string | only if runing on Azure cloud                                   | Used for Azure authentication                                      |   Value of `AKEYLESS_AZURE_OBJECT_ID` environment variable                                                       |
| akeyless_gcp_audience   | string | only if runing on GCP cloud                                    | Used for GCP authentication                    | Value of `AKEYLESS_GCP_AUDIENCE` environment variable""                                                      |
| akeyless_k8s_service_account_token   | string | only if running on k8s   | The K8S service account token encoded in base64. Used for K8S authentication                    | Value of `AKEYLESS_K8S_SERVICE_ACCOUNT_TOKEN` environment variable""                                                      |
| akeyless_k8s_auth_config_name   | string | only if running on k8s                               | The K8S Auth config name. Used for K8S authentication                    | Value of `AKEYLESS_K8S_AUTH_CONFIG_NAME` environment variable""                                                      |
| akeyless_target_folder   | string | no                                    | Target folder to store keys                     | Value of `AKEYLESS_TARGET_FOLDER` environment variable"" or '/' if not provided                                                     |
| key_metadata_file   | string | yes                                    | File path location where key metadata used by the plugin is persisted.                     |                                                      |

The plugin supports HCL/JSON configuration. Sample Plugin Configuration:
```hcl
{        
    akeyless_access_key_id = "p-xxxxxxx"
    akeyless_access_key = "XXXXXXXXXXXX"    
}
```



## Prerequisites

* Running gateway
* Auth method attached to role with following permissions: Create/Read/List on keys
