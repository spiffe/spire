# Protocol Documentation
<a name="top"/>

## Table of Contents


* [plugin.proto](#plugin.proto)
  
    * [ConfigureRequest](#spire.common.plugin.ConfigureRequest)
  
    * [ConfigureResponse](#spire.common.plugin.ConfigureResponse)
  
    * [GetPluginInfoRequest](#spire.common.plugin.GetPluginInfoRequest)
  
    * [GetPluginInfoResponse](#spire.common.plugin.GetPluginInfoResponse)
  
    * [PluginInfoReply](#spire.common.plugin.PluginInfoReply)
  
    * [PluginInfoRequest](#spire.common.plugin.PluginInfoRequest)
  
    * [StopReply](#spire.common.plugin.StopReply)
  
    * [StopRequest](#spire.common.plugin.StopRequest)
  
  
  
  
    * [Server](#spire.common.plugin.Server)
  


* [upstreamca.proto](#upstreamca.proto)
  
    * [SubmitCSRRequest](#spire.server.upstreamca.SubmitCSRRequest)
  
    * [SubmitCSRResponse](#spire.server.upstreamca.SubmitCSRResponse)
  
  
  
  
    * [UpstreamCA](#spire.server.upstreamca.UpstreamCA)
  

* [Scalar Value Types](#scalar-value-types)



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
Represents a list of configuration problems found in the configuration string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| errorList | [string](#string) | repeated | A list of errors. |






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






<a name="spire.common.plugin.PluginInfoReply"/>

### PluginInfoReply



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| pluginInfo | [GetPluginInfoResponse](#spire.common.plugin.GetPluginInfoResponse) | repeated |  |






<a name="spire.common.plugin.PluginInfoRequest"/>

### PluginInfoRequest







<a name="spire.common.plugin.StopReply"/>

### StopReply







<a name="spire.common.plugin.StopRequest"/>

### StopRequest






 

 

 


<a name="spire.common.plugin.Server"/>

### Server


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Stop | [StopRequest](#spire.common.plugin.StopRequest) | [StopReply](#spire.common.plugin.StopRequest) |  |
| PluginInfo | [PluginInfoRequest](#spire.common.plugin.PluginInfoRequest) | [PluginInfoReply](#spire.common.plugin.PluginInfoRequest) |  |

 



<a name="upstreamca.proto"/>
<p align="right"><a href="#top">Top</a></p>

## upstreamca.proto
Responsible for processing Certificate Signing Requests for intermediate signing certificates
(or from Node Agents if the user does not want the Control Plane to retain signing material).
This plugin will manage/own the Trust Bundles for the Control Plane, and act as the interface for upstream CAs.


<a name="spire.server.upstreamca.SubmitCSRRequest"/>

### SubmitCSRRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| csr | [bytes](#bytes) |  | Certificate signing request. |






<a name="spire.server.upstreamca.SubmitCSRResponse"/>

### SubmitCSRResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cert | [bytes](#bytes) |  | Signed certificate |
| upstreamTrustBundle | [bytes](#bytes) |  | Upstream trust bundle. |





 

 

 


<a name="spire.server.upstreamca.UpstreamCA"/>

### UpstreamCA


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Configure | [spire.common.plugin.ConfigureRequest](#spire.common.plugin.ConfigureRequest) | [spire.common.plugin.ConfigureResponse](#spire.common.plugin.ConfigureRequest) | Responsible for configuration of the plugin. |
| GetPluginInfo | [spire.common.plugin.GetPluginInfoRequest](#spire.common.plugin.GetPluginInfoRequest) | [spire.common.plugin.GetPluginInfoResponse](#spire.common.plugin.GetPluginInfoRequest) | Returns the  version and related metadata of the installed plugin. |
| SubmitCSR | [SubmitCSRRequest](#spire.server.upstreamca.SubmitCSRRequest) | [SubmitCSRResponse](#spire.server.upstreamca.SubmitCSRRequest) | Will take in a CSR and submit it to the upstream CA for signing(“upstream” CA can be local self-signed root in simple case). |

 



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

