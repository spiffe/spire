# Protocol Documentation
<a name="top"/>

## Table of Contents


* [common.proto](#common.proto)
  
    * [ConfigureRequest](#sri_proto.ConfigureRequest)
  
    * [ConfigureResponse](#sri_proto.ConfigureResponse)
  
    * [GetPluginInfoRequest](#sri_proto.GetPluginInfoRequest)
  
    * [GetPluginInfoResponse](#sri_proto.GetPluginInfoResponse)
  
  
  
  


* [control_plane_ca.proto](#control_plane_ca.proto)
  
    * [FetchCertificateRequest](#sri_proto.FetchCertificateRequest)
  
    * [FetchCertificateResponse](#sri_proto.FetchCertificateResponse)
  
    * [GenerateCsrRequest](#sri_proto.GenerateCsrRequest)
  
    * [GenerateCsrResponse](#sri_proto.GenerateCsrResponse)
  
    * [LoadCertificateRequest](#sri_proto.LoadCertificateRequest)
  
    * [LoadCertificateResponse](#sri_proto.LoadCertificateResponse)
  
    * [SignCsrRequest](#sri_proto.SignCsrRequest)
  
    * [SignCsrResponse](#sri_proto.SignCsrResponse)
  
  
  
  
    * [ControlPlaneCA](#sri_proto.ControlPlaneCA)
  

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





 

 

 

 



<a name="control_plane_ca.proto"/>
<p align="right"><a href="#top">Top</a></p>

## control_plane_ca.proto
Responsible for processing CSR requests from Node Agents if the Control Plane is configured to carry an intermediate signing certificate.
This plugin is also responsible for generating the CSR necessary for an intermediate signing cert, as well as storing the key in memory or hardware.


<a name="sri_proto.FetchCertificateRequest"/>

### FetchCertificateRequest
Represents an empty request.






<a name="sri_proto.FetchCertificateResponse"/>

### FetchCertificateResponse
Represents a response with a stored intermediate certificate.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| storedIntermediateCert | [bytes](#bytes) |  | Stored intermediate certificate. |






<a name="sri_proto.GenerateCsrRequest"/>

### GenerateCsrRequest
Represents an empty request.






<a name="sri_proto.GenerateCsrResponse"/>

### GenerateCsrResponse
Represents a response with a certificate signing request.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| csr | [bytes](#bytes) |  | Certificate signing request. |






<a name="sri_proto.LoadCertificateRequest"/>

### LoadCertificateRequest
Represents a request with a signed intermediate certificate.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| signedIntermediateCert | [bytes](#bytes) |  | Signed intermediate certificate. |






<a name="sri_proto.LoadCertificateResponse"/>

### LoadCertificateResponse
Represents an empty response.






<a name="sri_proto.SignCsrRequest"/>

### SignCsrRequest
Represents a request with a certificate signing request.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| csr | [bytes](#bytes) |  | Certificate signing request. |






<a name="sri_proto.SignCsrResponse"/>

### SignCsrResponse
Represents a response with a signed certificate.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| signedCertificate | [bytes](#bytes) |  | Signed certificate. |





 

 

 


<a name="sri_proto.ControlPlaneCA"/>

### ControlPlaneCA


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Configure | [ConfigureRequest](#sri_proto.ConfigureRequest) | [ConfigureResponse](#sri_proto.ConfigureRequest) | Responsible for configuration of the plugin. |
| GetPluginInfo | [GetPluginInfoRequest](#sri_proto.GetPluginInfoRequest) | [GetPluginInfoResponse](#sri_proto.GetPluginInfoRequest) | Returns the  version and related metadata of the installed plugin. |
| SignCsr | [SignCsrRequest](#sri_proto.SignCsrRequest) | [SignCsrResponse](#sri_proto.SignCsrRequest) | Interface will take in a CSR and sign it with the stored intermediate certificate. |
| GenerateCsr | [GenerateCsrRequest](#sri_proto.GenerateCsrRequest) | [GenerateCsrResponse](#sri_proto.GenerateCsrRequest) | Used for generating a CSR for the intermediate signing certificate. The CSR will then be submitted to the CA plugin for signing. |
| FetchCertificate | [FetchCertificateRequest](#sri_proto.FetchCertificateRequest) | [FetchCertificateResponse](#sri_proto.FetchCertificateRequest) | Used to read the stored Intermediate CP cert. |
| LoadCertificate | [LoadCertificateRequest](#sri_proto.LoadCertificateRequest) | [LoadCertificateResponse](#sri_proto.LoadCertificateRequest) | Used for setting/storing the signed intermediate certificate. |

 



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

