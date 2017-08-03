# Protocol Documentation
<a name="top"/>

## Table of Contents
* [node_resolver.proto](#node_resolver.proto)
* [Empty](#proto.Empty)
* [NodeResolution](#proto.NodeResolution)
* [NodeResolutionList](#proto.NodeResolutionList)
* [ResolveRequest](#proto.ResolveRequest)
* [ResolveResponse](#proto.ResolveResponse)
* [ResolveResponse.MapEntry](#proto.ResolveResponse.MapEntry)
* [NodeResolver](#proto.NodeResolver)
* [Scalar Value Types](#scalar-value-types)

<a name="node_resolver.proto"/>
<p align="right"><a href="#top">Top</a></p>

## node_resolver.proto

Resolves the derived selectors for a given Node Agent. This mapping will be stored, and used to further derive which workloads the Node Agent is authorized to run.

<a name="proto.Empty"/>

### Empty

Represents an empty message

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |

<a name="proto.NodeResolution"/>

### NodeResolution

Represents a a type with a selectorType and a selector.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectorType | [string](#string) | optional | It represents the type of attestation used in attesting the entity (Eg: AWS, K8). |
| selector | [string](#string) | optional | A native property of an entity ( node or workload ). |

<a name="proto.NodeResolutionList"/>

### NodeResolutionList

Represents a type with a list of NodeResolution.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| list | [NodeResolution](#proto.NodeResolution) | repeated | A list of NodeResolution. |

<a name="proto.ResolveRequest"/>

### ResolveRequest

Represents a request with a list of BaseSPIFFEIDs.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeIdList | [string](#string) | repeated | A list of BaseSPIFFE Ids. |


<a name="proto.ResolveResponse"/>

### ResolveResponse

Represents a response with a map of SPIFFE ID to a list of Noderesolution.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| map | [ResolveResponse.MapEntry](#proto.ResolveResponse.MapEntry) | repeated | Map[SPIFFE_ID] => NodeResolutionList. |


<a name="proto.ResolveResponse.MapEntry"/>

### ResolveResponse.MapEntry

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) | optional |  |
| value | [NodeResolutionList](#proto.NodeResolutionList) | optional |  |

<a name="proto.NodeResolver"/>

### NodeResolver

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Configure | [ConfigureRequest](#proto.ConfigureRequest) | [ConfigureResponse](#proto.ConfigureResponse) | Responsible for configuration of the plugin. |
| GetPluginInfo | [GetPluginInfoRequest](#proto.GetPluginInfoRequest) | [GetPluginInfoResponse](#proto.GetPluginInfoResponse) | Returns the  version and related metadata of the installed plugin. |
| Resolve | [ResolveRequest](#proto.ResolveRequest) | [ResolveResponse](#proto.ResolveResponse) | Retrieves a list of properties reflecting the current state of a particular node(s). |

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
