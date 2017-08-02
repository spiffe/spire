# Protocol Documentation
<a name="top"/>

## Table of Contents
* [control_plane_ca.proto](#control_plane_ca.proto)
* [FetchCertificateRequest](#proto.FetchCertificateRequest)
* [FetchCertificateResponse](#proto.FetchCertificateResponse)
* [GenerateCsrRequest](#proto.GenerateCsrRequest)
* [GenerateCsrResponse](#proto.GenerateCsrResponse)
* [LoadCertificateRequest](#proto.LoadCertificateRequest)
* [LoadCertificateResponse](#proto.LoadCertificateResponse)
* [SignCsrRequest](#proto.SignCsrRequest)
* [SignCsrResponse](#proto.SignCsrResponse)
* [ControlPlaneCA](#proto.ControlPlaneCA)
* [Scalar Value Types](#scalar-value-types)

<a name="control_plane_ca.proto"/>
<p align="right"><a href="#top">Top</a></p>

## control_plane_ca.proto

Responsible for processing CSR requests from Node Agents if the Control Plane is configured to carry an intermediate signing certificate.
This plugin is also responsible for generating the CSR necessary for an intermediate signing cert, as well as storing the key in memory or hardware.

<a name="proto.FetchCertificateRequest"/>

### FetchCertificateRequest

Represents an empty request.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |


<a name="proto.FetchCertificateResponse"/>

### FetchCertificateResponse

Represents a response with a stored intermediate certificate.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| storedIntermediateCert | [bytes](#bytes) | optional | Stored intermediate certificate. |


<a name="proto.GenerateCsrRequest"/>

### GenerateCsrRequest

Represents an empty request.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |


<a name="proto.GenerateCsrResponse"/>

### GenerateCsrResponse

Represents a response with a certificate signing request.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| csr | [bytes](#bytes) | optional | Certificate signing request. |


<a name="proto.LoadCertificateRequest"/>

### LoadCertificateRequest

Represents a request with a signed intermediate certificate.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| signedIntermediateCert | [bytes](#bytes) | optional | Signed intermediate certificate. |


<a name="proto.LoadCertificateResponse"/>

### LoadCertificateResponse

Represents an empty response.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |


<a name="proto.SignCsrRequest"/>

### SignCsrRequest

Represents a request with a certificate signing request.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| csr | [bytes](#bytes) | optional | Certificate signing request. |


<a name="proto.SignCsrResponse"/>

### SignCsrResponse

Represents a response with a signed certificate.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| signedCertificate | [bytes](#bytes) | optional | Signed certificate. |

<a name="proto.ControlPlaneCA"/>

### ControlPlaneCA

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Configure | [ConfigureRequest](#proto.ConfigureRequest) | [ConfigureResponse](#proto.ConfigureResponse) | Responsible for configuration of the plugin. |
| GetPluginInfo | [GetPluginInfoRequest](#proto.GetPluginInfoRequest) | [GetPluginInfoResponse](#proto.GetPluginInfoResponse) | Returns the  version and related metadata of the installed plugin. |
| SignCsr | [SignCsrRequest](#proto.SignCsrRequest) | [SignCsrResponse](#proto.SignCsrResponse) | Interface will take in a CSR and sign it with the stored intermediate certificate. |
| GenerateCsr | [GenerateCsrRequest](#proto.GenerateCsrRequest) | [GenerateCsrResponse](#proto.GenerateCsrResponse) | Used for generating a CSR for the intermediate signing certificate. The CSR will then be submitted to the CA plugin for signing. |
| FetchCertificate | [FetchCertificateRequest](#proto.FetchCertificateRequest) | [FetchCertificateResponse](#proto.FetchCertificateResponse) | Used to read the stored Intermediate CP cert. |
| LoadCertificate | [LoadCertificateRequest](#proto.LoadCertificateRequest) | [LoadCertificateResponse](#proto.LoadCertificateResponse) | Used for setting/storing the signed intermediate certificate. |

<a name="scalar-value-types"/>

## Scalar Value Types

| .proto Type | Notes | C++ Type | Java Type | Python Type |
| ----------- | ----- | -------- | --------- | ----------- |
| <a name="double"/> double |  | double | double | float |
| <a name="float"/> float |  | float | float | float |
| <a name="int32"/> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int |
| <a name="int64"/> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long |
| <a name="uint32"/> uint32 | Uses variable-length encoding. | uint32 | int | int/long |
| <a name="uint64"/> uint64 | Uses variable-length encoding. | uint64 | long | int/long |
| <a name="sint32"/> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int |
| <a name="sint64"/> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long |
| <a name="fixed32"/> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int |
| <a name="fixed64"/> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long |
| <a name="sfixed32"/> sfixed32 | Always four bytes. | int32 | int | int |
| <a name="sfixed64"/> sfixed64 | Always eight bytes. | int64 | long | int/long |
| <a name="bool"/> bool |  | bool | boolean | boolean |
| <a name="string"/> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode |
| <a name="bytes"/> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str |
