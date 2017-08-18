# Protocol Documentation
<a name="top"/>

## Table of Contents


* [common.proto](#common.proto)
  
    * [ConfigureRequest](#sri_proto.ConfigureRequest)
  
    * [ConfigureResponse](#sri_proto.ConfigureResponse)
  
    * [GetPluginInfoRequest](#sri_proto.GetPluginInfoRequest)
  
    * [GetPluginInfoResponse](#sri_proto.GetPluginInfoResponse)
  
    * [PluginInfoReply](#sri_proto.PluginInfoReply)
  
    * [PluginInfoRequest](#sri_proto.PluginInfoRequest)
  
    * [StopReply](#sri_proto.StopReply)
  
    * [StopRequest](#sri_proto.StopRequest)
  
  
  
  
    * [Server](#sri_proto.Server)
  


* [upstream_ca.proto](#upstream_ca.proto)
  
    * [SubmitCSRRequest](#sri_proto.SubmitCSRRequest)
  
    * [SubmitCSRResponse](#sri_proto.SubmitCSRResponse)
  
  
  
  
    * [UpstreamCA](#sri_proto.UpstreamCA)
  

* [Scalar Value Types](#scalar-value-types)



<a name="common.proto"/>
<p align="right"><a href="#top">Top</a></p>

## common.proto



<a name="sri_proto.ConfigureRequest"/>

### ConfigureRequest
Represents the plugin-specific configuration string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| configuration | [string](#string) |  | The configuration for the plugin. |






<a name="sri_proto.ConfigureResponse"/>

### ConfigureResponse
Represents a list of configuration problems found in the configuration string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| errorList | [string](#string) | repeated | A list of errors. |






<a name="sri_proto.GetPluginInfoRequest"/>

### GetPluginInfoRequest
Represents an empty request.






<a name="sri_proto.GetPluginInfoResponse"/>

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






<a name="sri_proto.PluginInfoReply"/>

### PluginInfoReply



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| pluginInfo | [GetPluginInfoResponse](#sri_proto.GetPluginInfoResponse) | repeated |  |






<a name="sri_proto.PluginInfoRequest"/>

### PluginInfoRequest







<a name="sri_proto.StopReply"/>

### StopReply







<a name="sri_proto.StopRequest"/>

### StopRequest






 

 

 


<a name="sri_proto.Server"/>

### Server


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Stop | [StopRequest](#sri_proto.StopRequest) | [StopReply](#sri_proto.StopRequest) |  |
| PluginInfo | [PluginInfoRequest](#sri_proto.PluginInfoRequest) | [PluginInfoReply](#sri_proto.PluginInfoRequest) |  |

 



<a name="upstream_ca.proto"/>
<p align="right"><a href="#top">Top</a></p>

## upstream_ca.proto
Responsible for processing Certificate Signing Requests for intermediate signing certificates
(or from Node Agents if the user does not want the Control Plane to retain signing material).
This plugin will manage/own the Trust Bundles for the Control Plane, and act as the interface for upstream CAs.


<a name="sri_proto.SubmitCSRRequest"/>

### SubmitCSRRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| csr | [bytes](#bytes) |  | Certificate signing request. |






<a name="sri_proto.SubmitCSRResponse"/>

### SubmitCSRResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cert | [bytes](#bytes) |  | Signed certificate |
| upstreamTrustBundle | [bytes](#bytes) |  | Upstream trust bundle. |





 

 

 


<a name="sri_proto.UpstreamCA"/>

### UpstreamCA


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Configure | [ConfigureRequest](#sri_proto.ConfigureRequest) | [ConfigureResponse](#sri_proto.ConfigureRequest) | Responsible for configuration of the plugin. |
| GetPluginInfo | [GetPluginInfoRequest](#sri_proto.GetPluginInfoRequest) | [GetPluginInfoResponse](#sri_proto.GetPluginInfoRequest) | Returns the  version and related metadata of the installed plugin. |
| SubmitCSR | [SubmitCSRRequest](#sri_proto.SubmitCSRRequest) | [SubmitCSRResponse](#sri_proto.SubmitCSRRequest) | Will take in a CSR and submit it to the upstream CA for signing(“upstream” CA can be local self-signed root in simple case). |

 



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

