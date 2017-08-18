# Protocol Documentation
<a name="top"/>

## Table of Contents


* [registration.proto](#registration.proto)
  
    * [CreateEntryRequest](#sri_proto.CreateEntryRequest)
  
    * [CreateEntryResponse](#sri_proto.CreateEntryResponse)
  
    * [CreateFederatedBundleRequest](#sri_proto.CreateFederatedBundleRequest)
  
    * [CreateFederatedBundleResponse](#sri_proto.CreateFederatedBundleResponse)
  
    * [CreateFederatedEntryRequest](#sri_proto.CreateFederatedEntryRequest)
  
    * [CreateFederatedEntryResponse](#sri_proto.CreateFederatedEntryResponse)
  
    * [DeleteEntryRequest](#sri_proto.DeleteEntryRequest)
  
    * [DeleteEntryResponse](#sri_proto.DeleteEntryResponse)
  
    * [DeleteFederatedBundleRequest](#sri_proto.DeleteFederatedBundleRequest)
  
    * [DeleteFederatedBundleResponse](#sri_proto.DeleteFederatedBundleResponse)
  
    * [FederatedBundle](#sri_proto.FederatedBundle)
  
    * [FederatedEntry](#sri_proto.FederatedEntry)
  
    * [ListAttestorEntriesRequest](#sri_proto.ListAttestorEntriesRequest)
  
    * [ListAttestorEntriesResponse](#sri_proto.ListAttestorEntriesResponse)
  
    * [ListFederatedBundlesRequest](#sri_proto.ListFederatedBundlesRequest)
  
    * [ListFederatedBundlesResponse](#sri_proto.ListFederatedBundlesResponse)
  
    * [ListSelectorEntriesRequest](#sri_proto.ListSelectorEntriesRequest)
  
    * [ListSelectorEntriesResponse](#sri_proto.ListSelectorEntriesResponse)
  
    * [ListSpiffeEntriesRequest](#sri_proto.ListSpiffeEntriesRequest)
  
    * [ListSpiffeEntriesResponse](#sri_proto.ListSpiffeEntriesResponse)
  
    * [RegisteredEntry](#sri_proto.RegisteredEntry)
  
    * [UpdateFederatedBundleRequest](#sri_proto.UpdateFederatedBundleRequest)
  
    * [UpdateFederatedBundleResponse](#sri_proto.UpdateFederatedBundleResponse)
  
  
  
  
    * [node](#sri_proto.node)
  

* [Scalar Value Types](#scalar-value-types)



<a name="registration.proto"/>
<p align="right"><a href="#top">Top</a></p>

## registration.proto



<a name="sri_proto.CreateEntryRequest"/>

### CreateEntryRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [RegisteredEntry](#sri_proto.RegisteredEntry) |  |  |






<a name="sri_proto.CreateEntryResponse"/>

### CreateEntryResponse







<a name="sri_proto.CreateFederatedBundleRequest"/>

### CreateFederatedBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#sri_proto.FederatedBundle) |  |  |






<a name="sri_proto.CreateFederatedBundleResponse"/>

### CreateFederatedBundleResponse







<a name="sri_proto.CreateFederatedEntryRequest"/>

### CreateFederatedEntryRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedEntry | [FederatedEntry](#sri_proto.FederatedEntry) |  |  |






<a name="sri_proto.CreateFederatedEntryResponse"/>

### CreateFederatedEntryResponse







<a name="sri_proto.DeleteEntryRequest"/>

### DeleteEntryRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectorType | [string](#string) |  |  |
| selector | [string](#string) |  |  |






<a name="sri_proto.DeleteEntryResponse"/>

### DeleteEntryResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedEntryList | [FederatedEntry](#sri_proto.FederatedEntry) | repeated |  |






<a name="sri_proto.DeleteFederatedBundleRequest"/>

### DeleteFederatedBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federateBundleSpiffeId | [string](#string) |  |  |






<a name="sri_proto.DeleteFederatedBundleResponse"/>

### DeleteFederatedBundleResponse







<a name="sri_proto.FederatedBundle"/>

### FederatedBundle



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federateBundleSpiffeId | [string](#string) |  |  |
| federatedBundle | [bytes](#bytes) |  |  |
| ttl | [int32](#int32) |  |  |






<a name="sri_proto.FederatedEntry"/>

### FederatedEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [RegisteredEntry](#sri_proto.RegisteredEntry) |  |  |
| federateBundleSpiffeIdList | [string](#string) | repeated |  |






<a name="sri_proto.ListAttestorEntriesRequest"/>

### ListAttestorEntriesRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestor | [string](#string) |  |  |






<a name="sri_proto.ListAttestorEntriesResponse"/>

### ListAttestorEntriesResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedEntryList | [FederatedEntry](#sri_proto.FederatedEntry) | repeated |  |






<a name="sri_proto.ListFederatedBundlesRequest"/>

### ListFederatedBundlesRequest







<a name="sri_proto.ListFederatedBundlesResponse"/>

### ListFederatedBundlesResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federateBundleSpiffeIdList | [string](#string) | repeated |  |






<a name="sri_proto.ListSelectorEntriesRequest"/>

### ListSelectorEntriesRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectorType | [string](#string) |  |  |
| selector | [string](#string) |  |  |






<a name="sri_proto.ListSelectorEntriesResponse"/>

### ListSelectorEntriesResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedEntryList | [FederatedEntry](#sri_proto.FederatedEntry) | repeated |  |






<a name="sri_proto.ListSpiffeEntriesRequest"/>

### ListSpiffeEntriesRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeId | [string](#string) |  |  |






<a name="sri_proto.ListSpiffeEntriesResponse"/>

### ListSpiffeEntriesResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedEntryList | [FederatedEntry](#sri_proto.FederatedEntry) | repeated |  |






<a name="sri_proto.RegisteredEntry"/>

### RegisteredEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectorType | [string](#string) |  |  |
| selector | [string](#string) |  |  |
| attestor | [string](#string) |  |  |
| spiffeId | [string](#string) |  |  |
| ttl | [int32](#int32) |  |  |






<a name="sri_proto.UpdateFederatedBundleRequest"/>

### UpdateFederatedBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#sri_proto.FederatedBundle) |  |  |






<a name="sri_proto.UpdateFederatedBundleResponse"/>

### UpdateFederatedBundleResponse






 

 

 


<a name="sri_proto.node"/>

### node


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| CreateFederatedEntry | [CreateFederatedEntryRequest](#sri_proto.CreateFederatedEntryRequest) | [CreateFederatedEntryResponse](#sri_proto.CreateFederatedEntryRequest) |  |
| CreateFederatedBundle | [CreateFederatedBundleRequest](#sri_proto.CreateFederatedBundleRequest) | [CreateFederatedBundleResponse](#sri_proto.CreateFederatedBundleRequest) |  |
| ListFederatedBundles | [ListFederatedBundlesRequest](#sri_proto.ListFederatedBundlesRequest) | [ListFederatedBundlesResponse](#sri_proto.ListFederatedBundlesRequest) |  |
| UpdateFederatedBundle | [UpdateFederatedBundleRequest](#sri_proto.UpdateFederatedBundleRequest) | [UpdateFederatedBundleResponse](#sri_proto.UpdateFederatedBundleRequest) |  |
| DeleteFederatedBundle | [DeleteFederatedBundleRequest](#sri_proto.DeleteFederatedBundleRequest) | [DeleteFederatedBundleResponse](#sri_proto.DeleteFederatedBundleRequest) |  |
| CreateEntry | [CreateEntryRequest](#sri_proto.CreateEntryRequest) | [CreateEntryResponse](#sri_proto.CreateEntryRequest) |  |
| ListAttestorEntries | [ListAttestorEntriesRequest](#sri_proto.ListAttestorEntriesRequest) | [ListAttestorEntriesResponse](#sri_proto.ListAttestorEntriesRequest) |  |
| ListSelectorEntries | [ListSelectorEntriesRequest](#sri_proto.ListSelectorEntriesRequest) | [ListSelectorEntriesResponse](#sri_proto.ListSelectorEntriesRequest) |  |
| ListSpiffeEntries | [ListSpiffeEntriesRequest](#sri_proto.ListSpiffeEntriesRequest) | [ListSpiffeEntriesResponse](#sri_proto.ListSpiffeEntriesRequest) |  |
| DeleteEntry | [DeleteEntryRequest](#sri_proto.DeleteEntryRequest) | [DeleteEntryResponse](#sri_proto.DeleteEntryRequest) |  |

 



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

