# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [keymanager.proto](#keymanager.proto)
    - [FetchPrivateKeyRequest](#spire.agent.keymanager.FetchPrivateKeyRequest)
    - [FetchPrivateKeyResponse](#spire.agent.keymanager.FetchPrivateKeyResponse)
    - [GenerateKeyPairRequest](#spire.agent.keymanager.GenerateKeyPairRequest)
    - [GenerateKeyPairResponse](#spire.agent.keymanager.GenerateKeyPairResponse)
    - [StorePrivateKeyRequest](#spire.agent.keymanager.StorePrivateKeyRequest)
    - [StorePrivateKeyResponse](#spire.agent.keymanager.StorePrivateKeyResponse)
  
  
  
    - [KeyManager](#spire.agent.keymanager.KeyManager)
  

- [Scalar Value Types](#scalar-value-types)



<a name="keymanager.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## keymanager.proto



<a name="spire.agent.keymanager.FetchPrivateKeyRequest"></a>

### FetchPrivateKeyRequest
Represents an empty request






<a name="spire.agent.keymanager.FetchPrivateKeyResponse"></a>

### FetchPrivateKeyResponse
Represents a private key


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| privateKey | [bytes](#bytes) |  | Private key |






<a name="spire.agent.keymanager.GenerateKeyPairRequest"></a>

### GenerateKeyPairRequest
Represents an empty request






<a name="spire.agent.keymanager.GenerateKeyPairResponse"></a>

### GenerateKeyPairResponse
Represents a public and private key pair


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| publicKey | [bytes](#bytes) |  | Public key |
| privateKey | [bytes](#bytes) |  | Private key |






<a name="spire.agent.keymanager.StorePrivateKeyRequest"></a>

### StorePrivateKeyRequest
Represents a private key


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| privateKey | [bytes](#bytes) |  | Private key |






<a name="spire.agent.keymanager.StorePrivateKeyResponse"></a>

### StorePrivateKeyResponse
Represents an empty response





 

 

 


<a name="spire.agent.keymanager.KeyManager"></a>

### KeyManager


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| GenerateKeyPair | [GenerateKeyPairRequest](#spire.agent.keymanager.GenerateKeyPairRequest) | [GenerateKeyPairResponse](#spire.agent.keymanager.GenerateKeyPairResponse) | Creates a new key pair. |
| StorePrivateKey | [StorePrivateKeyRequest](#spire.agent.keymanager.StorePrivateKeyRequest) | [StorePrivateKeyResponse](#spire.agent.keymanager.StorePrivateKeyResponse) | Persists a private key to the key manager&#39;s storage system. |
| FetchPrivateKey | [FetchPrivateKeyRequest](#spire.agent.keymanager.FetchPrivateKeyRequest) | [FetchPrivateKeyResponse](#spire.agent.keymanager.FetchPrivateKeyResponse) | Returns the most recently stored private key. For use after node restarts. |
| Configure | [.spire.common.plugin.ConfigureRequest](#spire.common.plugin.ConfigureRequest) | [.spire.common.plugin.ConfigureResponse](#spire.common.plugin.ConfigureResponse) | Applies the plugin configuration and returns configuration errors. |
| GetPluginInfo | [.spire.common.plugin.GetPluginInfoRequest](#spire.common.plugin.GetPluginInfoRequest) | [.spire.common.plugin.GetPluginInfoResponse](#spire.common.plugin.GetPluginInfoResponse) | Returns the version and related metadata of the plugin. |

 



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

