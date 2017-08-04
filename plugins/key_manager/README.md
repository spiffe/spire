# Protocol Documentation
<a name="top"/>

## Table of Contents


* [common.proto](#common.proto)
  
    * [ConfigureRequest](#proto.ConfigureRequest)
  
    * [ConfigureResponse](#proto.ConfigureResponse)
  
    * [GetPluginInfoRequest](#proto.GetPluginInfoRequest)
  
    * [GetPluginInfoResponse](#proto.GetPluginInfoResponse)
  
  
  
  


* [key_manager.proto](#key_manager.proto)
  
    * [FetchPrivateKeyRequest](#proto.FetchPrivateKeyRequest)
  
    * [FetchPrivateKeyResponse](#proto.FetchPrivateKeyResponse)
  
    * [GenerateKeyPairRequest](#proto.GenerateKeyPairRequest)
  
    * [GenerateKeyPairResponse](#proto.GenerateKeyPairResponse)
  
  
  
  
    * [KeyManager](#proto.KeyManager)
  

* [Scalar Value Types](#scalar-value-types)



<a name="common.proto"/>
<p align="right"><a href="#top">Top</a></p>

## common.proto



<a name="proto.ConfigureRequest"/>

### ConfigureRequest
represents the plugin-specific configuration string


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| configuration | [string](#string) |  |  |






<a name="proto.ConfigureResponse"/>

### ConfigureResponse
represents a list of configuration problems found in the configuration string


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| errorList | [string](#string) | repeated |  |






<a name="proto.GetPluginInfoRequest"/>

### GetPluginInfoRequest







<a name="proto.GetPluginInfoResponse"/>

### GetPluginInfoResponse
represents the plugin metadata


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





 

 

 

 



<a name="key_manager.proto"/>
<p align="right"><a href="#top">Top</a></p>

## key_manager.proto



<a name="proto.FetchPrivateKeyRequest"/>

### FetchPrivateKeyRequest







<a name="proto.FetchPrivateKeyResponse"/>

### FetchPrivateKeyResponse
represents a private key


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| privateKey | [bytes](#bytes) |  |  |






<a name="proto.GenerateKeyPairRequest"/>

### GenerateKeyPairRequest







<a name="proto.GenerateKeyPairResponse"/>

### GenerateKeyPairResponse
represents a public and private key pair


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| publicKey | [bytes](#bytes) |  |  |
| privateKey | [bytes](#bytes) |  |  |





 

 

 


<a name="proto.KeyManager"/>

### KeyManager


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| GenerateKeyPair | [GenerateKeyPairRequest](#proto.GenerateKeyPairRequest) | [GenerateKeyPairResponse](#proto.GenerateKeyPairRequest) | Creates a key pair that is bound to hardware |
| FetchPrivateKey | [FetchPrivateKeyRequest](#proto.FetchPrivateKeyRequest) | [FetchPrivateKeyResponse](#proto.FetchPrivateKeyRequest) | Returns previously generated private key. For use after node restarts |
| Configure | [ConfigureRequest](#proto.ConfigureRequest) | [ConfigureResponse](#proto.ConfigureRequest) | Applies the plugin configuration and returns configuration errors |
| GetPluginInfo | [GetPluginInfoRequest](#proto.GetPluginInfoRequest) | [GetPluginInfoResponse](#proto.GetPluginInfoRequest) | Returns the version and related metadata of the plugin |

 



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

