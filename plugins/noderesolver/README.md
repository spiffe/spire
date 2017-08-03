# Protocol Documentation
<a name="top"/>

## Table of Contents


* [common.proto](#common.proto)
  
    * [ConfigureRequest](#proto.ConfigureRequest)
  
    * [ConfigureResponse](#proto.ConfigureResponse)
  
    * [GetPluginInfoRequest](#proto.GetPluginInfoRequest)
  
    * [GetPluginInfoResponse](#proto.GetPluginInfoResponse)
  
  
  
  


* [node_resolution.proto](#node_resolution.proto)
  
    * [Empty](#proto.Empty)
  
    * [NodeResolution](#proto.NodeResolution)
  
    * [NodeResolutionList](#proto.NodeResolutionList)
  
    * [ResolveRequest](#proto.ResolveRequest)
  
    * [ResolveResponse](#proto.ResolveResponse)
  
    * [ResolveResponse.MapEntry](#proto.ResolveResponse.MapEntry)
  
  
  
  
    * [node](#proto.node)
  

* [Scalar Value Types](#scalar-value-types)



<a name="common.proto"/>
<p align="right"><a href="#top">Top</a></p>

## common.proto



<a name="proto.ConfigureRequest"/>

### ConfigureRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| configuration | [string](#string) |  |  |






<a name="proto.ConfigureResponse"/>

### ConfigureResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| errorList | [string](#string) | repeated |  |






<a name="proto.GetPluginInfoRequest"/>

### GetPluginInfoRequest







<a name="proto.GetPluginInfoResponse"/>

### GetPluginInfoResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| pluginName | [string](#string) |  |  |
| description | [string](#string) |  |  |
| dateCreated | [string](#string) |  |  |
| location | [string](#string) |  |  |
| version | [string](#string) |  |  |
| author | [string](#string) |  |  |
| company | [string](#string) |  |  |





 

 

 

 



<a name="node_resolution.proto"/>
<p align="right"><a href="#top">Top</a></p>

## node_resolution.proto



<a name="proto.Empty"/>

### Empty







<a name="proto.NodeResolution"/>

### NodeResolution



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectorType | [string](#string) |  |  |
| selector | [string](#string) |  |  |






<a name="proto.NodeResolutionList"/>

### NodeResolutionList



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| list | [NodeResolution](#proto.NodeResolution) | repeated |  |






<a name="proto.ResolveRequest"/>

### ResolveRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| physicalSpiffeIdList | [string](#string) | repeated |  |






<a name="proto.ResolveResponse"/>

### ResolveResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| map | [ResolveResponse.MapEntry](#proto.ResolveResponse.MapEntry) | repeated |  |






<a name="proto.ResolveResponse.MapEntry"/>

### ResolveResponse.MapEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [NodeResolutionList](#proto.NodeResolutionList) |  |  |





 

 

 


<a name="proto.node"/>

### node


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Configure | [ConfigureRequest](#proto.ConfigureRequest) | [ConfigureResponse](#proto.ConfigureRequest) |  |
| GetPluginInfo | [GetPluginInfoRequest](#proto.GetPluginInfoRequest) | [GetPluginInfoResponse](#proto.GetPluginInfoRequest) |  |
| Resolve | [ResolveRequest](#proto.ResolveRequest) | [ResolveResponse](#proto.ResolveRequest) |  |

 



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

