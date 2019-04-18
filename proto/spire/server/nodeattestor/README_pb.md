# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [nodeattestor.proto](#nodeattestor.proto)
    - [AttestRequest](#spire.agent.nodeattestor.AttestRequest)
    - [AttestResponse](#spire.agent.nodeattestor.AttestResponse)
  
  
  
    - [NodeAttestor](#spire.agent.nodeattestor.NodeAttestor)
  

- [Scalar Value Types](#scalar-value-types)



<a name="nodeattestor.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## nodeattestor.proto



<a name="spire.agent.nodeattestor.AttestRequest"></a>

### AttestRequest
Represents a request to attest a node.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestationData | [spire.common.AttestationData](#spire.common.AttestationData) |  | A type which contains attestation data for specific platform. |
| attestedBefore | [bool](#bool) |  | Is true if the Base SPIFFE ID is present in the Attested Node table. |
| response | [bytes](#bytes) |  | Challenge response |






<a name="spire.agent.nodeattestor.AttestResponse"></a>

### AttestResponse
Represents a response when attesting a node.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| valid | [bool](#bool) |  | True/False |
| baseSPIFFEID | [string](#string) |  | Used by the Server to validate the SPIFFE Id in the Certificate signing request. |
| challenge | [bytes](#bytes) |  | Challenge required for attestation |
| selectors | [spire.common.Selector](#spire.common.Selector) | repeated | Optional list of selectors |





 

 

 


<a name="spire.agent.nodeattestor.NodeAttestor"></a>

### NodeAttestor


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Attest | [AttestRequest](#spire.agent.nodeattestor.AttestRequest) stream | [AttestResponse](#spire.agent.nodeattestor.AttestResponse) stream | Attesta a node. |
| Configure | [.spire.common.plugin.ConfigureRequest](#spire.common.plugin.ConfigureRequest) | [.spire.common.plugin.ConfigureResponse](#spire.common.plugin.ConfigureResponse) | Responsible for configuration of the plugin. |
| GetPluginInfo | [.spire.common.plugin.GetPluginInfoRequest](#spire.common.plugin.GetPluginInfoRequest) | [.spire.common.plugin.GetPluginInfoResponse](#spire.common.plugin.GetPluginInfoResponse) | Returns the version and related metadata of the installed plugin. |

 



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

