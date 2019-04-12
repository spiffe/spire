# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [workloadattestor.proto](#workloadattestor.proto)
    - [AttestRequest](#spire.agent.workloadattestor.AttestRequest)
    - [AttestResponse](#spire.agent.workloadattestor.AttestResponse)
  
  
  
    - [WorkloadAttestor](#spire.agent.workloadattestor.WorkloadAttestor)
  

- [Scalar Value Types](#scalar-value-types)



<a name="workloadattestor.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## workloadattestor.proto



<a name="spire.agent.workloadattestor.AttestRequest"></a>

### AttestRequest
Represents the workload PID.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| pid | [int32](#int32) |  | Workload PID |






<a name="spire.agent.workloadattestor.AttestResponse"></a>

### AttestResponse
Represents a list of selectors resolved for a given PID.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectors | [spire.common.Selector](#spire.common.Selector) | repeated | List of selectors |





 

 

 


<a name="spire.agent.workloadattestor.WorkloadAttestor"></a>

### WorkloadAttestor


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Attest | [AttestRequest](#spire.agent.workloadattestor.AttestRequest) | [AttestResponse](#spire.agent.workloadattestor.AttestResponse) | Returns a list of selectors resolved for a given PID |
| Configure | [.spire.common.plugin.ConfigureRequest](#spire.common.plugin.ConfigureRequest) | [.spire.common.plugin.ConfigureResponse](#spire.common.plugin.ConfigureResponse) | Applies the plugin configuration and returns configuration errors |
| GetPluginInfo | [.spire.common.plugin.GetPluginInfoRequest](#spire.common.plugin.GetPluginInfoRequest) | [.spire.common.plugin.GetPluginInfoResponse](#spire.common.plugin.GetPluginInfoResponse) | Returns the version and related metadata of the plugin |

 



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

