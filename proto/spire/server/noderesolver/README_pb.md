# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [noderesolver.proto](#noderesolver.proto)
    - [ResolveRequest](#spire.server.noderesolver.ResolveRequest)
    - [ResolveResponse](#spire.server.noderesolver.ResolveResponse)
    - [ResolveResponse.MapEntry](#spire.server.noderesolver.ResolveResponse.MapEntry)
  
  
  
    - [NodeResolver](#spire.server.noderesolver.NodeResolver)
  

- [Scalar Value Types](#scalar-value-types)



<a name="noderesolver.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## noderesolver.proto



<a name="spire.server.noderesolver.ResolveRequest"></a>

### ResolveRequest
Represents a request with a list of BaseSPIFFEIDs.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeIdList | [string](#string) | repeated | A list of BaseSPIFFE Ids. |






<a name="spire.server.noderesolver.ResolveResponse"></a>

### ResolveResponse
Represents a response with a map of SPIFFE ID to a list of Selectors.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| map | [ResolveResponse.MapEntry](#spire.server.noderesolver.ResolveResponse.MapEntry) | repeated | Map[SPIFFE_ID] =&gt; Selectors. |






<a name="spire.server.noderesolver.ResolveResponse.MapEntry"></a>

### ResolveResponse.MapEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [spire.common.Selectors](#spire.common.Selectors) |  |  |





 

 

 


<a name="spire.server.noderesolver.NodeResolver"></a>

### NodeResolver


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Resolve | [ResolveRequest](#spire.server.noderesolver.ResolveRequest) | [ResolveResponse](#spire.server.noderesolver.ResolveResponse) | Retrieves a list of properties reflecting the current state of a particular node(s). |
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

