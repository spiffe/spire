# Protocol Documentation
<a name="top"/>

## Table of Contents


* [common.proto](#common.proto)
  
    * [ConfigureRequest](#proto.ConfigureRequest)
  
    * [ConfigureResponse](#proto.ConfigureResponse)
  
    * [GetPluginInfoRequest](#proto.GetPluginInfoRequest)
  
    * [GetPluginInfoResponse](#proto.GetPluginInfoResponse)
  
  
  
  


* [upstream_ca.proto](#upstream_ca.proto)
  
    * [SubmitCSRRequest](#proto.SubmitCSRRequest)
  
    * [SubmitCSRResponse](#proto.SubmitCSRResponse)
  
  
  
  
    * [UpstreamCA](#proto.UpstreamCA)
  

* [Scalar Value Types](#scalar-value-types)



<a name="common.proto"/>
<p align="right"><a href="#top">Top</a></p>

## common.proto



<a name="proto.ConfigureRequest"/>

### ConfigureRequest
Represents the plugin-specific configuration string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| configuration | [string](#string) |  | The configuration for the plugin. |






<a name="proto.ConfigureResponse"/>

### ConfigureResponse
Represents a list of configuration problems found in the configuration string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| errorList | [string](#string) | repeated | A list of errors. |






<a name="proto.GetPluginInfoRequest"/>

### GetPluginInfoRequest
Represents an empty request.






<a name="proto.GetPluginInfoResponse"/>

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





 

 

 

 



<a name="upstream_ca.proto"/>
<p align="right"><a href="#top">Top</a></p>

## upstream_ca.proto
Responsible for processing Certificate Signing Requests for intermediate signing certificates
(or from Node Agents if the user does not want the Control Plane to retain signing material).
This plugin will manage/own the Trust Bundles for the Control Plane, and act as the interface for upstream CAs.


<a name="proto.SubmitCSRRequest"/>

### SubmitCSRRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| csr | [bytes](#bytes) |  | Certificate signing request. |






<a name="proto.SubmitCSRResponse"/>

### SubmitCSRResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cert | [bytes](#bytes) |  | Signed certificate |
| upstreamTrustBundle | [bytes](#bytes) |  | Upstream trust bundle. |





 

 

 


<a name="proto.UpstreamCA"/>

### UpstreamCA


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Configure | [ConfigureRequest](#proto.ConfigureRequest) | [ConfigureResponse](#proto.ConfigureRequest) | Responsible for configuration of the plugin. |
| GetPluginInfo | [GetPluginInfoRequest](#proto.GetPluginInfoRequest) | [GetPluginInfoResponse](#proto.GetPluginInfoRequest) | Returns the  version and related metadata of the installed plugin. |
| SubmitCSR | [SubmitCSRRequest](#proto.SubmitCSRRequest) | [SubmitCSRResponse](#proto.SubmitCSRRequest) | Will take in a CSR and submit it to the upstream CA for signing(“upstream” CA can be local self-signed root in simple case). |

 



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

