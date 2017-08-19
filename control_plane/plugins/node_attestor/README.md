# Protocol Documentation
<a name="top"/>

## Table of Contents


* [plugin.proto](#plugin.proto)
  
    * [ConfigureRequest](#sriplugin.ConfigureRequest)
  
    * [ConfigureResponse](#sriplugin.ConfigureResponse)
  
    * [GetPluginInfoRequest](#sriplugin.GetPluginInfoRequest)
  
    * [GetPluginInfoResponse](#sriplugin.GetPluginInfoResponse)
  
    * [PluginInfoReply](#sriplugin.PluginInfoReply)
  
    * [PluginInfoRequest](#sriplugin.PluginInfoRequest)
  
    * [StopReply](#sriplugin.StopReply)
  
    * [StopRequest](#sriplugin.StopRequest)
  
  
  
  
    * [Server](#sriplugin.Server)
  


* [node_attestor.proto](#node_attestor.proto)
  
    * [AttestRequest](#cpnodeattestor.AttestRequest)
  
    * [AttestResponse](#cpnodeattestor.AttestResponse)
  
    * [AttestedData](#cpnodeattestor.AttestedData)
  
  
  
  
    * [NodeAttestor](#cpnodeattestor.NodeAttestor)
  

* [Scalar Value Types](#scalar-value-types)



<a name="plugin.proto"/>
<p align="right"><a href="#top">Top</a></p>

## plugin.proto



<a name="sriplugin.ConfigureRequest"/>

### ConfigureRequest
Represents the plugin-specific configuration string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| configuration | [string](#string) |  | The configuration for the plugin. |






<a name="sriplugin.ConfigureResponse"/>

### ConfigureResponse
Represents a list of configuration problems found in the configuration string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| errorList | [string](#string) | repeated | A list of errors. |






<a name="sriplugin.GetPluginInfoRequest"/>

### GetPluginInfoRequest
Represents an empty request.






<a name="sriplugin.GetPluginInfoResponse"/>

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






<a name="sriplugin.PluginInfoReply"/>

### PluginInfoReply



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| pluginInfo | [GetPluginInfoResponse](#sriplugin.GetPluginInfoResponse) | repeated |  |






<a name="sriplugin.PluginInfoRequest"/>

### PluginInfoRequest







<a name="sriplugin.StopReply"/>

### StopReply







<a name="sriplugin.StopRequest"/>

### StopRequest






 

 

 


<a name="sriplugin.Server"/>

### Server


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Stop | [StopRequest](#sriplugin.StopRequest) | [StopReply](#sriplugin.StopRequest) |  |
| PluginInfo | [PluginInfoRequest](#sriplugin.PluginInfoRequest) | [PluginInfoReply](#sriplugin.PluginInfoRequest) |  |

 



<a name="node_attestor.proto"/>
<p align="right"><a href="#top">Top</a></p>

## node_attestor.proto
Responsible for validating the Node Agent’s Attested Data.


<a name="cpnodeattestor.AttestRequest"/>

### AttestRequest
Represents a request to attest a node.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedData | [AttestedData](#cpnodeattestor.AttestedData) |  | A type which contains attestation data for specific platform. |
| attestedBefore | [bool](#bool) |  | Is true if the Base SPIFFE ID is present in the Attested Node table. |






<a name="cpnodeattestor.AttestResponse"/>

### AttestResponse
Represents a response when attesting a node.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| valid | [bool](#bool) |  | True/False |
| baseSPIFFEID | [string](#string) |  | Used for the Control Plane to validate the SPIFFE Id in the Certificate signing request. |






<a name="cpnodeattestor.AttestedData"/>

### AttestedData
A type which contains attestation data for specific platform.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [string](#string) |  | Type of attestation to perform. |
| data | [bytes](#bytes) |  | The attestetion data. |





 

 

 


<a name="cpnodeattestor.NodeAttestor"/>

### NodeAttestor


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Configure | [sriplugin.ConfigureRequest](#sriplugin.ConfigureRequest) | [sriplugin.ConfigureResponse](#sriplugin.ConfigureRequest) | Responsible for configuration of the plugin. |
| GetPluginInfo | [sriplugin.GetPluginInfoRequest](#sriplugin.GetPluginInfoRequest) | [sriplugin.GetPluginInfoResponse](#sriplugin.GetPluginInfoRequest) | Returns the  version and related metadata of the installed plugin. |
| Attest | [AttestRequest](#cpnodeattestor.AttestRequest) | [AttestResponse](#cpnodeattestor.AttestRequest) | Attesta a node. |

 



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

