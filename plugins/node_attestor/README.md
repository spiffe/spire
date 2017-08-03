# Protocol Documentation
<a name="top"/>

## Table of Contents
* [node_attestor.proto](#node_attestor.proto)
* [AttestRequest](#proto.AttestRequest)
* [AttestResponse](#proto.AttestResponse)
* [AttestedData](#proto.AttestedData)
* [NodeAttestor](#proto.NodeAttestor)
* [Scalar Value Types](#scalar-value-types)

<a name="node_attestor.proto"/>
<p align="right"><a href="#top">Top</a></p>

## node_attestor.proto

Responsible for validating the Node Agent's Attested Data.

<a name="proto.AttestRequest"/>

### AttestRequest

Represents a request to attest a node.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedData | [AttestedData](#proto.AttestedData) | optional | A type which contains attestation data for specific platform. |
| attestedBefore | [bool](#bool) | optional | Is true if the Base SPIFFE ID is present in the Attested Node table. |


<a name="proto.AttestResponse"/>

### AttestResponse

Represents a response when attesting a node.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| valid | [bool](#bool) | optional | True/False |
| baseSPIFFEID | [string](#string) | optional | Used for the Control Plane to validate the SPIFFE Id in the Certificate signing request. |


<a name="proto.AttestedData"/>

### AttestedData

A type which contains attestation data for specific platform.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [string](#string) | optional | Type of attestation to perform. |
| data | [bytes](#bytes) | optional | The attestetion data. |

<a name="proto.NodeAttestor"/>

### NodeAttestor

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Configure | [ConfigureRequest](#proto.ConfigureRequest) | [ConfigureResponse](#proto.ConfigureResponse) | Responsible for configuration of the plugin. |
| GetPluginInfo | [GetPluginInfoRequest](#proto.GetPluginInfoRequest) | [GetPluginInfoResponse](#proto.GetPluginInfoResponse) | Returns the  version and related metadata of the installed plugin. |
| Attest | [AttestRequest](#proto.AttestRequest) | [AttestResponse](#proto.AttestResponse) | Attesta a node. |

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
