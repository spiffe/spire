# Protocol Documentation
<a name="top"/>

## Table of Contents


* [registration.proto](#registration.proto)
  
    * [CreateEntryRequest](#control_plane_proto.CreateEntryRequest)
  
    * [CreateEntryResponse](#control_plane_proto.CreateEntryResponse)
  
    * [CreateFederatedBundleRequest](#control_plane_proto.CreateFederatedBundleRequest)
  
    * [CreateFederatedBundleResponse](#control_plane_proto.CreateFederatedBundleResponse)
  
    * [CreateFederatedEntryRequest](#control_plane_proto.CreateFederatedEntryRequest)
  
    * [CreateFederatedEntryResponse](#control_plane_proto.CreateFederatedEntryResponse)
  
    * [DeleteEntryRequest](#control_plane_proto.DeleteEntryRequest)
  
    * [DeleteEntryResponse](#control_plane_proto.DeleteEntryResponse)
  
    * [DeleteFederatedBundleRequest](#control_plane_proto.DeleteFederatedBundleRequest)
  
    * [DeleteFederatedBundleResponse](#control_plane_proto.DeleteFederatedBundleResponse)
  
    * [FederatedBundle](#control_plane_proto.FederatedBundle)
  
    * [FederatedEntry](#control_plane_proto.FederatedEntry)
  
    * [ListAttestorEntriesRequest](#control_plane_proto.ListAttestorEntriesRequest)
  
    * [ListAttestorEntriesResponse](#control_plane_proto.ListAttestorEntriesResponse)
  
    * [ListFederatedBundlesRequest](#control_plane_proto.ListFederatedBundlesRequest)
  
    * [ListFederatedBundlesResponse](#control_plane_proto.ListFederatedBundlesResponse)
  
    * [ListSelectorEntriesRequest](#control_plane_proto.ListSelectorEntriesRequest)
  
    * [ListSelectorEntriesResponse](#control_plane_proto.ListSelectorEntriesResponse)
  
    * [ListSpiffeEntriesRequest](#control_plane_proto.ListSpiffeEntriesRequest)
  
    * [ListSpiffeEntriesResponse](#control_plane_proto.ListSpiffeEntriesResponse)
  
    * [RegisteredEntry](#control_plane_proto.RegisteredEntry)
  
    * [UpdateFederatedBundleRequest](#control_plane_proto.UpdateFederatedBundleRequest)
  
    * [UpdateFederatedBundleResponse](#control_plane_proto.UpdateFederatedBundleResponse)
  
  
  
  
    * [node](#control_plane_proto.node)
  

* [Scalar Value Types](#scalar-value-types)



<a name="registration.proto"/>
<p align="right"><a href="#top">Top</a></p>

## registration.proto



<a name="control_plane_proto.CreateEntryRequest"/>

### CreateEntryRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [RegisteredEntry](#control_plane_proto.RegisteredEntry) |  |  |






<a name="control_plane_proto.CreateEntryResponse"/>

### CreateEntryResponse







<a name="control_plane_proto.CreateFederatedBundleRequest"/>

### CreateFederatedBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#control_plane_proto.FederatedBundle) |  |  |






<a name="control_plane_proto.CreateFederatedBundleResponse"/>

### CreateFederatedBundleResponse







<a name="control_plane_proto.CreateFederatedEntryRequest"/>

### CreateFederatedEntryRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedEntry | [FederatedEntry](#control_plane_proto.FederatedEntry) |  |  |






<a name="control_plane_proto.CreateFederatedEntryResponse"/>

### CreateFederatedEntryResponse







<a name="control_plane_proto.DeleteEntryRequest"/>

### DeleteEntryRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectorType | [string](#string) |  |  |
| selector | [string](#string) |  |  |






<a name="control_plane_proto.DeleteEntryResponse"/>

### DeleteEntryResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedEntryList | [FederatedEntry](#control_plane_proto.FederatedEntry) | repeated |  |






<a name="control_plane_proto.DeleteFederatedBundleRequest"/>

### DeleteFederatedBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federateBundleSpiffeId | [string](#string) |  |  |






<a name="control_plane_proto.DeleteFederatedBundleResponse"/>

### DeleteFederatedBundleResponse







<a name="control_plane_proto.FederatedBundle"/>

### FederatedBundle



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federateBundleSpiffeId | [string](#string) |  |  |
| federatedBundle | [bytes](#bytes) |  |  |
| ttl | [int32](#int32) |  |  |






<a name="control_plane_proto.FederatedEntry"/>

### FederatedEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [RegisteredEntry](#control_plane_proto.RegisteredEntry) |  |  |
| federateBundleSpiffeIdList | [string](#string) | repeated |  |






<a name="control_plane_proto.ListAttestorEntriesRequest"/>

### ListAttestorEntriesRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestor | [string](#string) |  |  |






<a name="control_plane_proto.ListAttestorEntriesResponse"/>

### ListAttestorEntriesResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedEntryList | [FederatedEntry](#control_plane_proto.FederatedEntry) | repeated |  |






<a name="control_plane_proto.ListFederatedBundlesRequest"/>

### ListFederatedBundlesRequest







<a name="control_plane_proto.ListFederatedBundlesResponse"/>

### ListFederatedBundlesResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federateBundleSpiffeIdList | [string](#string) | repeated |  |






<a name="control_plane_proto.ListSelectorEntriesRequest"/>

### ListSelectorEntriesRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectorType | [string](#string) |  |  |
| selector | [string](#string) |  |  |






<a name="control_plane_proto.ListSelectorEntriesResponse"/>

### ListSelectorEntriesResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedEntryList | [FederatedEntry](#control_plane_proto.FederatedEntry) | repeated |  |






<a name="control_plane_proto.ListSpiffeEntriesRequest"/>

### ListSpiffeEntriesRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeId | [string](#string) |  |  |






<a name="control_plane_proto.ListSpiffeEntriesResponse"/>

### ListSpiffeEntriesResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedEntryList | [FederatedEntry](#control_plane_proto.FederatedEntry) | repeated |  |






<a name="control_plane_proto.RegisteredEntry"/>

### RegisteredEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectorType | [string](#string) |  |  |
| selector | [string](#string) |  |  |
| attestor | [string](#string) |  |  |
| spiffeId | [string](#string) |  |  |
| ttl | [int32](#int32) |  |  |






<a name="control_plane_proto.UpdateFederatedBundleRequest"/>

### UpdateFederatedBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#control_plane_proto.FederatedBundle) |  |  |






<a name="control_plane_proto.UpdateFederatedBundleResponse"/>

### UpdateFederatedBundleResponse






 

 

 


<a name="control_plane_proto.node"/>

### node


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| CreateFederatedEntry | [CreateFederatedEntryRequest](#control_plane_proto.CreateFederatedEntryRequest) | [CreateFederatedEntryResponse](#control_plane_proto.CreateFederatedEntryRequest) |  |
| CreateFederatedBundle | [CreateFederatedBundleRequest](#control_plane_proto.CreateFederatedBundleRequest) | [CreateFederatedBundleResponse](#control_plane_proto.CreateFederatedBundleRequest) |  |
| ListFederatedBundles | [ListFederatedBundlesRequest](#control_plane_proto.ListFederatedBundlesRequest) | [ListFederatedBundlesResponse](#control_plane_proto.ListFederatedBundlesRequest) |  |
| UpdateFederatedBundle | [UpdateFederatedBundleRequest](#control_plane_proto.UpdateFederatedBundleRequest) | [UpdateFederatedBundleResponse](#control_plane_proto.UpdateFederatedBundleRequest) |  |
| DeleteFederatedBundle | [DeleteFederatedBundleRequest](#control_plane_proto.DeleteFederatedBundleRequest) | [DeleteFederatedBundleResponse](#control_plane_proto.DeleteFederatedBundleRequest) |  |
| CreateEntry | [CreateEntryRequest](#control_plane_proto.CreateEntryRequest) | [CreateEntryResponse](#control_plane_proto.CreateEntryRequest) |  |
| ListAttestorEntries | [ListAttestorEntriesRequest](#control_plane_proto.ListAttestorEntriesRequest) | [ListAttestorEntriesResponse](#control_plane_proto.ListAttestorEntriesRequest) |  |
| ListSelectorEntries | [ListSelectorEntriesRequest](#control_plane_proto.ListSelectorEntriesRequest) | [ListSelectorEntriesResponse](#control_plane_proto.ListSelectorEntriesRequest) |  |
| ListSpiffeEntries | [ListSpiffeEntriesRequest](#control_plane_proto.ListSpiffeEntriesRequest) | [ListSpiffeEntriesResponse](#control_plane_proto.ListSpiffeEntriesRequest) |  |
| DeleteEntry | [DeleteEntryRequest](#control_plane_proto.DeleteEntryRequest) | [DeleteEntryResponse](#control_plane_proto.DeleteEntryRequest) |  |

 



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

