# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [metricsservice.proto](#metricsservice.proto)
    - [AddSampleRequest](#spire.common.hostservices.AddSampleRequest)
    - [AddSampleResponse](#spire.common.hostservices.AddSampleResponse)
    - [EmitKeyRequest](#spire.common.hostservices.EmitKeyRequest)
    - [EmitKeyResponse](#spire.common.hostservices.EmitKeyResponse)
    - [IncrCounterRequest](#spire.common.hostservices.IncrCounterRequest)
    - [IncrCounterResponse](#spire.common.hostservices.IncrCounterResponse)
    - [Label](#spire.common.hostservices.Label)
    - [MeasureSinceRequest](#spire.common.hostservices.MeasureSinceRequest)
    - [MeasureSinceResponse](#spire.common.hostservices.MeasureSinceResponse)
    - [SetGaugeRequest](#spire.common.hostservices.SetGaugeRequest)
    - [SetGaugeResponse](#spire.common.hostservices.SetGaugeResponse)
  
  
  
    - [MetricsService](#spire.common.hostservices.MetricsService)
  

- [Scalar Value Types](#scalar-value-types)



<a name="metricsservice.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## metricsservice.proto



<a name="spire.common.hostservices.AddSampleRequest"></a>

### AddSampleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) | repeated |  |
| val | [float](#float) |  |  |
| labels | [Label](#spire.common.hostservices.Label) | repeated |  |






<a name="spire.common.hostservices.AddSampleResponse"></a>

### AddSampleResponse







<a name="spire.common.hostservices.EmitKeyRequest"></a>

### EmitKeyRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) | repeated |  |
| val | [float](#float) |  |  |






<a name="spire.common.hostservices.EmitKeyResponse"></a>

### EmitKeyResponse







<a name="spire.common.hostservices.IncrCounterRequest"></a>

### IncrCounterRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) | repeated |  |
| val | [float](#float) |  |  |
| labels | [Label](#spire.common.hostservices.Label) | repeated |  |






<a name="spire.common.hostservices.IncrCounterResponse"></a>

### IncrCounterResponse







<a name="spire.common.hostservices.Label"></a>

### Label



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| value | [string](#string) |  |  |






<a name="spire.common.hostservices.MeasureSinceRequest"></a>

### MeasureSinceRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) | repeated |  |
| time | [int64](#int64) |  | Unix time in nanoseconds |
| labels | [Label](#spire.common.hostservices.Label) | repeated |  |






<a name="spire.common.hostservices.MeasureSinceResponse"></a>

### MeasureSinceResponse







<a name="spire.common.hostservices.SetGaugeRequest"></a>

### SetGaugeRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) | repeated |  |
| val | [float](#float) |  |  |
| labels | [Label](#spire.common.hostservices.Label) | repeated |  |






<a name="spire.common.hostservices.SetGaugeResponse"></a>

### SetGaugeResponse






 

 

 


<a name="spire.common.hostservices.MetricsService"></a>

### MetricsService


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| SetGauge | [SetGaugeRequest](#spire.common.hostservices.SetGaugeRequest) | [SetGaugeResponse](#spire.common.hostservices.SetGaugeResponse) |  |
| EmitKey | [EmitKeyRequest](#spire.common.hostservices.EmitKeyRequest) | [EmitKeyResponse](#spire.common.hostservices.EmitKeyResponse) |  |
| IncrCounter | [IncrCounterRequest](#spire.common.hostservices.IncrCounterRequest) | [IncrCounterResponse](#spire.common.hostservices.IncrCounterResponse) |  |
| AddSample | [AddSampleRequest](#spire.common.hostservices.AddSampleRequest) | [AddSampleResponse](#spire.common.hostservices.AddSampleResponse) |  |
| MeasureSince | [MeasureSinceRequest](#spire.common.hostservices.MeasureSinceRequest) | [MeasureSinceResponse](#spire.common.hostservices.MeasureSinceResponse) |  |

 



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

