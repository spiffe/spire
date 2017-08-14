# Protocol Documentation
<a name="top"/>

## Table of Contents


* [registration.proto](#registration.proto)
  
    * [CreateEntryRequest](#proto.CreateEntryRequest)
  
    * [CreateEntryResponse](#proto.CreateEntryResponse)
  
    * [CreateFederatedBundleRequest](#proto.CreateFederatedBundleRequest)
  
    * [CreateFederatedBundleResponse](#proto.CreateFederatedBundleResponse)
  
    * [CreateFederatedEntryRequest](#proto.CreateFederatedEntryRequest)
  
    * [CreateFederatedEntryResponse](#proto.CreateFederatedEntryResponse)
  
    * [DeleteEntryRequest](#proto.DeleteEntryRequest)
  
    * [DeleteEntryResponse](#proto.DeleteEntryResponse)
  
    * [DeleteFederatedBundleRequest](#proto.DeleteFederatedBundleRequest)
  
    * [DeleteFederatedBundleResponse](#proto.DeleteFederatedBundleResponse)
  
    * [FederatedBundle](#proto.FederatedBundle)
  
    * [FederatedEntry](#proto.FederatedEntry)
  
    * [ListAttestorEntriesRequest](#proto.ListAttestorEntriesRequest)
  
    * [ListAttestorEntriesResponse](#proto.ListAttestorEntriesResponse)
  
    * [ListFederatedBundlesRequest](#proto.ListFederatedBundlesRequest)
  
    * [ListFederatedBundlesResponse](#proto.ListFederatedBundlesResponse)
  
    * [ListSelectorEntriesRequest](#proto.ListSelectorEntriesRequest)
  
    * [ListSelectorEntriesResponse](#proto.ListSelectorEntriesResponse)
  
    * [ListSpiffeEntriesRequest](#proto.ListSpiffeEntriesRequest)
  
    * [ListSpiffeEntriesResponse](#proto.ListSpiffeEntriesResponse)
  
    * [RegisteredEntry](#proto.RegisteredEntry)
  
    * [UpdateFederatedBundleRequest](#proto.UpdateFederatedBundleRequest)
  
    * [UpdateFederatedBundleResponse](#proto.UpdateFederatedBundleResponse)
  
  
  
  
    * [node](#proto.node)
  

* [Scalar Value Types](#scalar-value-types)



<a name="registration.proto"/>
<p align="right"><a href="#top">Top</a></p>

## registration.proto



<a name="proto.CreateEntryRequest"/>

### CreateEntryRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [RegisteredEntry](#proto.RegisteredEntry) |  |  |






<a name="proto.CreateEntryResponse"/>

### CreateEntryResponse







<a name="proto.CreateFederatedBundleRequest"/>

### CreateFederatedBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#proto.FederatedBundle) |  |  |






<a name="proto.CreateFederatedBundleResponse"/>

### CreateFederatedBundleResponse







<a name="proto.CreateFederatedEntryRequest"/>

### CreateFederatedEntryRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedEntry | [FederatedEntry](#proto.FederatedEntry) |  |  |






<a name="proto.CreateFederatedEntryResponse"/>

### CreateFederatedEntryResponse







<a name="proto.DeleteEntryRequest"/>

### DeleteEntryRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectorType | [string](#string) |  |  |
| selector | [string](#string) |  |  |






<a name="proto.DeleteEntryResponse"/>

### DeleteEntryResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedEntryList | [FederatedEntry](#proto.FederatedEntry) | repeated |  |






<a name="proto.DeleteFederatedBundleRequest"/>

### DeleteFederatedBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federateBundleSpiffeId | [string](#string) |  |  |






<a name="proto.DeleteFederatedBundleResponse"/>

### DeleteFederatedBundleResponse







<a name="proto.FederatedBundle"/>

### FederatedBundle



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federateBundleSpiffeId | [string](#string) |  |  |
| federatedBundle | [bytes](#bytes) |  |  |
| ttl | [int32](#int32) |  |  |






<a name="proto.FederatedEntry"/>

### FederatedEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [RegisteredEntry](#proto.RegisteredEntry) |  |  |
| federateBundleSpiffeIdList | [string](#string) | repeated |  |






<a name="proto.ListAttestorEntriesRequest"/>

### ListAttestorEntriesRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestor | [string](#string) |  |  |






<a name="proto.ListAttestorEntriesResponse"/>

### ListAttestorEntriesResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedEntryList | [FederatedEntry](#proto.FederatedEntry) | repeated |  |






<a name="proto.ListFederatedBundlesRequest"/>

### ListFederatedBundlesRequest







<a name="proto.ListFederatedBundlesResponse"/>

### ListFederatedBundlesResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federateBundleSpiffeIdList | [string](#string) | repeated |  |






<a name="proto.ListSelectorEntriesRequest"/>

### ListSelectorEntriesRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectorType | [string](#string) |  |  |
| selector | [string](#string) |  |  |






<a name="proto.ListSelectorEntriesResponse"/>

### ListSelectorEntriesResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedEntryList | [FederatedEntry](#proto.FederatedEntry) | repeated |  |






<a name="proto.ListSpiffeEntriesRequest"/>

### ListSpiffeEntriesRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeId | [string](#string) |  |  |






<a name="proto.ListSpiffeEntriesResponse"/>

### ListSpiffeEntriesResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedEntryList | [FederatedEntry](#proto.FederatedEntry) | repeated |  |






<a name="proto.RegisteredEntry"/>

### RegisteredEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectorType | [string](#string) |  |  |
| selector | [string](#string) |  |  |
| attestor | [string](#string) |  |  |
| spiffeId | [string](#string) |  |  |
| ttl | [int32](#int32) |  |  |






<a name="proto.UpdateFederatedBundleRequest"/>

### UpdateFederatedBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#proto.FederatedBundle) |  |  |






<a name="proto.UpdateFederatedBundleResponse"/>

### UpdateFederatedBundleResponse






 

 

 


<a name="proto.node"/>

### node


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| CreateFederatedEntry | [CreateFederatedEntryRequest](#proto.CreateFederatedEntryRequest) | [CreateFederatedEntryResponse](#proto.CreateFederatedEntryRequest) |  |
| CreateFederatedBundle | [CreateFederatedBundleRequest](#proto.CreateFederatedBundleRequest) | [CreateFederatedBundleResponse](#proto.CreateFederatedBundleRequest) |  |
| ListFederatedBundles | [ListFederatedBundlesRequest](#proto.ListFederatedBundlesRequest) | [ListFederatedBundlesResponse](#proto.ListFederatedBundlesRequest) |  |
| UpdateFederatedBundle | [UpdateFederatedBundleRequest](#proto.UpdateFederatedBundleRequest) | [UpdateFederatedBundleResponse](#proto.UpdateFederatedBundleRequest) |  |
| DeleteFederatedBundle | [DeleteFederatedBundleRequest](#proto.DeleteFederatedBundleRequest) | [DeleteFederatedBundleResponse](#proto.DeleteFederatedBundleRequest) |  |
| CreateEntry | [CreateEntryRequest](#proto.CreateEntryRequest) | [CreateEntryResponse](#proto.CreateEntryRequest) |  |
| ListAttestorEntries | [ListAttestorEntriesRequest](#proto.ListAttestorEntriesRequest) | [ListAttestorEntriesResponse](#proto.ListAttestorEntriesRequest) |  |
| ListSelectorEntries | [ListSelectorEntriesRequest](#proto.ListSelectorEntriesRequest) | [ListSelectorEntriesResponse](#proto.ListSelectorEntriesRequest) |  |
| ListSpiffeEntries | [ListSpiffeEntriesRequest](#proto.ListSpiffeEntriesRequest) | [ListSpiffeEntriesResponse](#proto.ListSpiffeEntriesRequest) |  |
| DeleteEntry | [DeleteEntryRequest](#proto.DeleteEntryRequest) | [DeleteEntryResponse](#proto.DeleteEntryRequest) |  |

 



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

