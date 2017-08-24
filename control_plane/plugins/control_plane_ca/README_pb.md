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
  


* [control_plane_ca.proto](#control_plane_ca.proto)
  
    * [FetchCertificateRequest](#controlplaneca.FetchCertificateRequest)
  
    * [FetchCertificateResponse](#controlplaneca.FetchCertificateResponse)
  
    * [GenerateCsrRequest](#controlplaneca.GenerateCsrRequest)
  
    * [GenerateCsrResponse](#controlplaneca.GenerateCsrResponse)
  
    * [LoadCertificateRequest](#controlplaneca.LoadCertificateRequest)
  
    * [LoadCertificateResponse](#controlplaneca.LoadCertificateResponse)
  
    * [SignCsrRequest](#controlplaneca.SignCsrRequest)
  
    * [SignCsrResponse](#controlplaneca.SignCsrResponse)
  
  
  
  
    * [ControlPlaneCA](#controlplaneca.ControlPlaneCA)
  

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

 



<a name="control_plane_ca.proto"/>
<p align="right"><a href="#top">Top</a></p>

## control_plane_ca.proto
Responsible for processing CSR requests from Node Agents if the Control Plane is configured to carry an intermediate signing certificate.
This plugin is also responsible for generating the CSR necessary for an intermediate signing cert, as well as storing the key in memory or hardware.


<a name="controlplaneca.FetchCertificateRequest"/>

### FetchCertificateRequest
Represents an empty request.






<a name="controlplaneca.FetchCertificateResponse"/>

### FetchCertificateResponse
Represents a response with a stored intermediate certificate.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| storedIntermediateCert | [bytes](#bytes) |  | Stored intermediate certificate. |






<a name="controlplaneca.GenerateCsrRequest"/>

### GenerateCsrRequest
Represents an empty request.






<a name="controlplaneca.GenerateCsrResponse"/>

### GenerateCsrResponse
Represents a response with a certificate signing request.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| csr | [bytes](#bytes) |  | Certificate signing request. |






<a name="controlplaneca.LoadCertificateRequest"/>

### LoadCertificateRequest
Represents a request with a signed intermediate certificate.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| signedIntermediateCert | [bytes](#bytes) |  | Signed intermediate certificate. |






<a name="controlplaneca.LoadCertificateResponse"/>

### LoadCertificateResponse
Represents an empty response.






<a name="controlplaneca.SignCsrRequest"/>

### SignCsrRequest
Represents a request with a certificate signing request.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| csr | [bytes](#bytes) |  | Certificate signing request. |






<a name="controlplaneca.SignCsrResponse"/>

### SignCsrResponse
Represents a response with a signed certificate.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| signedCertificate | [bytes](#bytes) |  | Signed certificate. |





 

 

 


<a name="controlplaneca.ControlPlaneCA"/>

### ControlPlaneCA


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Configure | [sriplugin.ConfigureRequest](#sriplugin.ConfigureRequest) | [sriplugin.ConfigureResponse](#sriplugin.ConfigureRequest) | Responsible for configuration of the plugin. |
| GetPluginInfo | [sriplugin.GetPluginInfoRequest](#sriplugin.GetPluginInfoRequest) | [sriplugin.GetPluginInfoResponse](#sriplugin.GetPluginInfoRequest) | Returns the  version and related metadata of the installed plugin. |
| SignCsr | [SignCsrRequest](#controlplaneca.SignCsrRequest) | [SignCsrResponse](#controlplaneca.SignCsrRequest) | Interface will take in a CSR and sign it with the stored intermediate certificate. |
| GenerateCsr | [GenerateCsrRequest](#controlplaneca.GenerateCsrRequest) | [GenerateCsrResponse](#controlplaneca.GenerateCsrRequest) | Used for generating a CSR for the intermediate signing certificate. The CSR will then be submitted to the CA plugin for signing. |
| FetchCertificate | [FetchCertificateRequest](#controlplaneca.FetchCertificateRequest) | [FetchCertificateResponse](#controlplaneca.FetchCertificateRequest) | Used to read the stored Intermediate CP cert. |
| LoadCertificate | [LoadCertificateRequest](#controlplaneca.LoadCertificateRequest) | [LoadCertificateResponse](#controlplaneca.LoadCertificateRequest) | Used for setting/storing the signed intermediate certificate. |

 



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

