# Server plugin: KeyManager "kms"

The `kms` key manager plugin leverages the AWS Key Management Service (KMS) to create, maintain and rotate key pairs (as [Customer master keys](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#master_keys), or CMKs), and sign SVIDs as needed, with the private key never leaving KMS.

## Build binary for linux

Building the binary requires go 1.15.0.

```bash
make build
```

## Configuration

The plugin accepts the following configuration options:

| Key               | Type   | Required                              | Description                                          |
| ----------------- | ------ | ------------------------------------- | ---------------------------------------------------- |
| access_key_id     | string | see [AWS KMS Access](#aws-kms-access) | The Access Key Id used to authenticate to KMS        |
| secret_access_key | string | see [AWS KMS Access](#aws-kms-access) | The Secret Access Key used to authenticate to KMS    |
| region            | string | yes                                   | The region where the keys will be stored             |
| key_prefix        | string | [1] see below                         | A unique prefix per server in the same trust domain. |

[1] `key_prefix` is **optional** when running a single server. When running more than one server, the prefix **must be set and must be different** on each one. This is a common scenario when running in HA mode. A valid key prefix can be any arbitrary string that uniquely identifies a server instance, like `SERVER_A/` or `prod-server-1/`. It defaults to `SPIRE_SERVER_KEY/` if not specified.

### AWS KMS Access

Access to AWS KMS can be given by either setting the `access_key_id` and `secret_access_key`, or by ensuring that the plugin runs on an EC2 instance with a given IAM role that has a specific set of permissions.

The IAM role must have an attached policy with the following permissions:

- `kms:CreateAlias`
- `kms:CreateKey`
- `kms:DescribeKey`
- `kms:GetPublicKey`
- `kms:ListAliases`
- `kms:ScheduleKeyDeletion`
- `kms:Sign`
- `kms:UpdateAlias`

## Sample plugin configuration

```
KeyManager "kms" {
    plugin_cmd = "path/to/bin/kms"
    plugin_checksum = "5c67edba8371f3ee5cc25dadf08b29281f7c747fa32de1323aba13aca60abe70"
    plugin_data {
        access_key_id = "ABIAXWLCWD9J4X873CQ2"
        secret_access_key = "CFiEHGH4N6LerdAt99SPwxmwoJ6IB1pPLJxTGoPN"
        region = "us-east-2"
    }
}
```

## Supported key types and TTL

The plugin creates CMKs of the same key type configured in the SPIRE Server. At the time of this writing the plugin supports all the set of keys supported by SPIRE: `rsa-2048`, `rsa-4096`, `ec-p256`, and `ec-p384`. It defaults to `ec-p256` if not specified.

In order to configure it you can set the `ca_key_type` value in the SPIRE Server config file.

You can also set the TTL that the plugin will use to rotate the CMKs by setting the `ca_ttl` config in the same config file.

For more info refer to the [Server configuration section](https://github.com/spiffe/spire/blob/master/doc/spire_server.md#server-configuration-file) in the SPIRE Server documentation and to the [full server config file](https://github.com/spiffe/spire/blob/master/conf/server/server_full.conf) for a complete Server config example.
