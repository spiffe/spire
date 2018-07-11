# Protocol Documentation
<a name="top"/>

## Table of Contents

- [plugin.proto](#plugin.proto)
    - [ConfigureRequest](#spire.common.plugin.ConfigureRequest)
    - [ConfigureResponse](#spire.common.plugin.ConfigureResponse)
    - [GetPluginInfoRequest](#spire.common.plugin.GetPluginInfoRequest)
    - [GetPluginInfoResponse](#spire.common.plugin.GetPluginInfoResponse)
  
  
  
  

- [keymanager.proto](#keymanager.proto)
    - [GenerateKeyRequest](#spire.server.keymanager.GenerateKeyRequest)
    - [GenerateKeyResponse](#spire.server.keymanager.GenerateKeyResponse)
    - [GetPublicKeyRequest](#spire.server.keymanager.GetPublicKeyRequest)
    - [GetPublicKeyResponse](#spire.server.keymanager.GetPublicKeyResponse)
    - [GetPublicKeysRequest](#spire.server.keymanager.GetPublicKeysRequest)
    - [GetPublicKeysResponse](#spire.server.keymanager.GetPublicKeysResponse)
    - [PublicKey](#spire.server.keymanager.PublicKey)
    - [SignDataRequest](#spire.server.keymanager.SignDataRequest)
    - [SignDataResponse](#spire.server.keymanager.SignDataResponse)
  
    - [HashAlgorithm](#spire.server.keymanager.HashAlgorithm)
    - [KeyAlgorithm](#spire.server.keymanager.KeyAlgorithm)
  
  
    - [KeyManager](#spire.server.keymanager.KeyManager)
  

- [Scalar Value Types](#scalar-value-types)



<a name="plugin.proto"/>
<p align="right"><a href="#top">Top</a></p>

## plugin.proto



<a name="spire.common.plugin.ConfigureRequest"/>

### ConfigureRequest
Represents the plugin-specific configuration string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| configuration | [string](#string) |  | The configuration for the plugin. |






<a name="spire.common.plugin.ConfigureResponse"/>

### ConfigureResponse
Represents a list of configuration problems
found in the configuration string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| errorList | [string](#string) | repeated | A list of errors |






<a name="spire.common.plugin.GetPluginInfoRequest"/>

### GetPluginInfoRequest
Represents an empty request.






<a name="spire.common.plugin.GetPluginInfoResponse"/>

### GetPluginInfoResponse
Represents the plugin metadata.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| category | [string](#string) |  |  |
| type | [string](#string) |  |  |
| description | [string](#string) |  |  |
| dateCreated | [string](#string) |  |  |
| location | [string](#string) |  |  |
| version | [string](#string) |  |  |
| author | [string](#string) |  |  |
| company | [string](#string) |  |  |





 

 

 

 



<a name="keymanager.proto"/>
<p align="right"><a href="#top">Top</a></p>

## keymanager.proto



<a name="spire.server.keymanager.GenerateKeyRequest"/>

### GenerateKeyRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key_id | [string](#string) |  |  |
| key_algorithm | [KeyAlgorithm](#spire.server.keymanager.KeyAlgorithm) |  |  |






<a name="spire.server.keymanager.GenerateKeyResponse"/>

### GenerateKeyResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| public_key | [PublicKey](#spire.server.keymanager.PublicKey) |  |  |






<a name="spire.server.keymanager.GetPublicKeyRequest"/>

### GetPublicKeyRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key_id | [string](#string) |  |  |






<a name="spire.server.keymanager.GetPublicKeyResponse"/>

### GetPublicKeyResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| public_key | [PublicKey](#spire.server.keymanager.PublicKey) |  |  |






<a name="spire.server.keymanager.GetPublicKeysRequest"/>

### GetPublicKeysRequest







<a name="spire.server.keymanager.GetPublicKeysResponse"/>

### GetPublicKeysResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| public_keys | [PublicKey](#spire.server.keymanager.PublicKey) | repeated |  |






<a name="spire.server.keymanager.PublicKey"/>

### PublicKey



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  |  |
| algorithm | [KeyAlgorithm](#spire.server.keymanager.KeyAlgorithm) |  |  |
| pkix_data | [bytes](#bytes) |  |  |






<a name="spire.server.keymanager.SignDataRequest"/>

### SignDataRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key_id | [string](#string) |  |  |
| hash_algorithm | [HashAlgorithm](#spire.server.keymanager.HashAlgorithm) |  |  |
| data | [bytes](#bytes) |  |  |






<a name="spire.server.keymanager.SignDataResponse"/>

### SignDataResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| signature | [bytes](#bytes) |  |  |





 


<a name="spire.server.keymanager.HashAlgorithm"/>

### HashAlgorithm


| Name | Number | Description |
| ---- | ------ | ----------- |
| UNSPECIFIED_HASH_ALGORITHM | 0 |  |
| SHA1 | 3 | These entries (and their values) line up with a subset of the go crypto.Hash constants |
| SHA224 | 4 |  |
| SHA256 | 5 |  |
| SHA384 | 6 |  |
| SHA512 | 7 |  |
| SHA3_224 | 10 |  |
| SHA3_256 | 11 |  |
| SHA3_384 | 12 |  |
| SHA3_512 | 13 |  |
| SHA512_224 | 14 |  |
| SHA512_256 | 15 |  |



<a name="spire.server.keymanager.KeyAlgorithm"/>

### KeyAlgorithm


| Name | Number | Description |
| ---- | ------ | ----------- |
| UNSPECIFIED_KEY_ALGORITHM | 0 |  |
| ECDSA_P256 | 1 |  |
| ECDSA_P384 | 2 |  |


 

 


<a name="spire.server.keymanager.KeyManager"/>

### KeyManager


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| GenerateKey | [GenerateKeyRequest](#spire.server.keymanager.GenerateKeyRequest) | [GenerateKeyResponse](#spire.server.keymanager.GenerateKeyRequest) | Generates a new key |
| GetPublicKey | [GetPublicKeyRequest](#spire.server.keymanager.GetPublicKeyRequest) | [GetPublicKeyResponse](#spire.server.keymanager.GetPublicKeyRequest) | Get a public key by key id |
| GetPublicKeys | [GetPublicKeysRequest](#spire.server.keymanager.GetPublicKeysRequest) | [GetPublicKeysResponse](#spire.server.keymanager.GetPublicKeysRequest) | Gets all public keys |
| SignData | [SignDataRequest](#spire.server.keymanager.SignDataRequest) | [SignDataResponse](#spire.server.keymanager.SignDataRequest) | Signs data with private key |
| Configure | [spire.common.plugin.ConfigureRequest](#spire.common.plugin.ConfigureRequest) | [spire.common.plugin.ConfigureResponse](#spire.common.plugin.ConfigureRequest) | Applies the plugin configuration |
| GetPluginInfo | [spire.common.plugin.GetPluginInfoRequest](#spire.common.plugin.GetPluginInfoRequest) | [spire.common.plugin.GetPluginInfoResponse](#spire.common.plugin.GetPluginInfoRequest) | Returns the version and related metadata of the installed plugin |

 



## Scalar Value Types

| .proto Type | Notes | C++ Type | Java Type | Python Type |
| ----------- | ----- | -------- | --------- | ----------- |
| <a name="double" /> double |  | double | double | float |
| <a name="float" /> float |  | float | float | float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long |
| <a name="bool" /> bool |  | bool | boolean | boolean |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str |

