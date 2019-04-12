# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [nodeattestor.proto](#nodeattestor.proto)
    - [FetchAttestationDataRequest](#spire.agent.nodeattestor.FetchAttestationDataRequest)
    - [FetchAttestationDataResponse](#spire.agent.nodeattestor.FetchAttestationDataResponse)
  
  
  
    - [NodeAttestor](#spire.agent.nodeattestor.NodeAttestor)
  

- [Scalar Value Types](#scalar-value-types)



<a name="nodeattestor.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## nodeattestor.proto



<a name="spire.agent.nodeattestor.FetchAttestationDataRequest"></a>

### FetchAttestationDataRequest
Represents an empty request


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| challenge | [bytes](#bytes) |  |  |






<a name="spire.agent.nodeattestor.FetchAttestationDataResponse"></a>

### FetchAttestationDataResponse
Represents the attested data and base SPIFFE ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestationData | [spire.common.AttestationData](#spire.common.AttestationData) |  | A type which contains attestation data for specific platform |
| spiffeId | [string](#string) |  | SPIFFE ID |
| response | [bytes](#bytes) |  | response to the challenge (if challenge was present) * |





 

 

 


<a name="spire.agent.nodeattestor.NodeAttestor"></a>

### NodeAttestor


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| FetchAttestationData | [FetchAttestationDataRequest](#spire.agent.nodeattestor.FetchAttestationDataRequest) stream | [FetchAttestationDataResponse](#spire.agent.nodeattestor.FetchAttestationDataResponse) stream | Returns the node attestation data for specific platform and the generated Base SPIFFE ID for CSR formation |
| Configure | [.spire.common.plugin.ConfigureRequest](#spire.common.plugin.ConfigureRequest) | [.spire.common.plugin.ConfigureResponse](#spire.common.plugin.ConfigureResponse) | Applies the plugin configuration and returns configuration errors |
| GetPluginInfo | [.spire.common.plugin.GetPluginInfoRequest](#spire.common.plugin.GetPluginInfoRequest) | [.spire.common.plugin.GetPluginInfoResponse](#spire.common.plugin.GetPluginInfoResponse) | Returns the version and related metadata of the plugin |

 



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

