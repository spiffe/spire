# Protocol Documentation
<a name="top"/>

## Table of Contents


* [common.proto](#common.proto)
  
    * [ConfigureRequest](#proto.ConfigureRequest)
  
    * [ConfigureResponse](#proto.ConfigureResponse)
  
    * [GetPluginInfoRequest](#proto.GetPluginInfoRequest)
  
    * [GetPluginInfoResponse](#proto.GetPluginInfoResponse)
  
  
  
  


* [data_store.proto](#data_store.proto)
  
    * [AttestedNodeEntry](#proto.AttestedNodeEntry)
  
    * [AttestedNodeUpdate](#proto.AttestedNodeUpdate)
  
    * [AttestedNodes](#proto.AttestedNodes)
  
    * [AttestorKey](#proto.AttestorKey)
  
    * [Empty](#proto.Empty)
  
    * [FederatedBundle](#proto.FederatedBundle)
  
    * [FederatedEntries](#proto.FederatedEntries)
  
    * [FederatedEntry](#proto.FederatedEntry)
  
    * [GroupedRegistrationKey](#proto.GroupedRegistrationKey)
  
    * [Key](#proto.Key)
  
    * [RegisteredEntries](#proto.RegisteredEntries)
  
    * [RegisteredEntry](#proto.RegisteredEntry)
  
    * [RegisteredEntryKey](#proto.RegisteredEntryKey)
  
    * [SelectorKey](#proto.SelectorKey)
  
    * [SelectorMapEntry](#proto.SelectorMapEntry)
  
  
  
  
    * [DataStore](#proto.DataStore)
  

* [Scalar Value Types](#scalar-value-types)



<a name="common.proto"/>
<p align="right"><a href="#top">Top</a></p>

## common.proto



<a name="proto.ConfigureRequest"/>

### ConfigureRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| configuration | [string](#string) |  |  |






<a name="proto.ConfigureResponse"/>

### ConfigureResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| errorList | [string](#string) | repeated |  |






<a name="proto.GetPluginInfoRequest"/>

### GetPluginInfoRequest







<a name="proto.GetPluginInfoResponse"/>

### GetPluginInfoResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| pluginName | [string](#string) |  |  |
| description | [string](#string) |  |  |
| dateCreated | [string](#string) |  |  |
| location | [string](#string) |  |  |
| version | [string](#string) |  |  |
| author | [string](#string) |  |  |
| company | [string](#string) |  |  |





 

 

 

 



<a name="data_store.proto"/>
<p align="right"><a href="#top">Top</a></p>

## data_store.proto



<a name="proto.AttestedNodeEntry"/>

### AttestedNodeEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| physicalSpiffeId | [string](#string) |  |  |
| attestedDataType | [string](#string) |  |  |
| certSerialNumber | [string](#string) |  |  |
| certExpiration | [int32](#int32) |  |  |






<a name="proto.AttestedNodeUpdate"/>

### AttestedNodeUpdate



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| physicalSpiffeId | [string](#string) |  |  |
| certSerialNumber | [string](#string) |  |  |
| certExpiration | [int32](#int32) |  |  |






<a name="proto.AttestedNodes"/>

### AttestedNodes



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| list | [AttestedNodeEntry](#proto.AttestedNodeEntry) | repeated |  |






<a name="proto.AttestorKey"/>

### AttestorKey



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestor | [string](#string) |  |  |






<a name="proto.Empty"/>

### Empty







<a name="proto.FederatedBundle"/>

### FederatedBundle



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeId | [string](#string) |  |  |
| trustBundle | [string](#string) |  |  |
| ttl | [int32](#int32) |  |  |






<a name="proto.FederatedEntries"/>

### FederatedEntries



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| list | [FederatedEntry](#proto.FederatedEntry) | repeated |  |






<a name="proto.FederatedEntry"/>

### FederatedEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryKey | [string](#string) |  |  |
| spiffeId | [string](#string) | repeated |  |






<a name="proto.GroupedRegistrationKey"/>

### GroupedRegistrationKey



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| guid | [string](#string) |  |  |






<a name="proto.Key"/>

### Key



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeId | [string](#string) |  |  |






<a name="proto.RegisteredEntries"/>

### RegisteredEntries



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| list | [RegisteredEntry](#proto.RegisteredEntry) | repeated |  |






<a name="proto.RegisteredEntry"/>

### RegisteredEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectorType | [string](#string) |  |  |
| selector | [string](#string) |  |  |
| attestor | [string](#string) |  |  |
| spiffeId | [string](#string) |  |  |
| ttl | [int32](#int32) |  |  |
| selectorGroup | [string](#string) |  |  |






<a name="proto.RegisteredEntryKey"/>

### RegisteredEntryKey



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectorType | [string](#string) |  |  |
| selector | [string](#string) |  |  |
| spiffeId | [string](#string) |  |  |






<a name="proto.SelectorKey"/>

### SelectorKey



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectorType | [string](#string) |  |  |
| selector | [string](#string) |  |  |






<a name="proto.SelectorMapEntry"/>

### SelectorMapEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| physicalSpiffeId | [string](#string) |  |  |
| selectorType | [string](#string) |  |  |
| selector | [string](#string) |  |  |





 

 

 


<a name="proto.DataStore"/>

### DataStore


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Configure | [ConfigureRequest](#proto.ConfigureRequest) | [ConfigureResponse](#proto.ConfigureRequest) |  |
| GetPluginInfo | [GetPluginInfoRequest](#proto.GetPluginInfoRequest) | [GetPluginInfoResponse](#proto.GetPluginInfoRequest) |  |
| CreateFederatedEntry | [FederatedBundle](#proto.FederatedBundle) | [Empty](#proto.FederatedBundle) |  |
| ListFederatedEntry | [Empty](#proto.Empty) | [FederatedEntries](#proto.Empty) |  |
| UpdateFederatedEntry | [FederatedBundle](#proto.FederatedBundle) | [Empty](#proto.FederatedBundle) |  |
| DeleteFederatedEntry | [Key](#proto.Key) | [Empty](#proto.Key) |  |
| CreateAttestedNodeEntry | [AttestedNodeEntry](#proto.AttestedNodeEntry) | [Empty](#proto.AttestedNodeEntry) |  |
| FetchAttestedNodeEntry | [Key](#proto.Key) | [AttestedNodeEntry](#proto.Key) |  |
| FetchStaleNodeEntries | [Empty](#proto.Empty) | [AttestedNodes](#proto.Empty) |  |
| UpdateAttestedNodeEntry | [AttestedNodeUpdate](#proto.AttestedNodeUpdate) | [Empty](#proto.AttestedNodeUpdate) |  |
| DeleteAttestedNodeEntry | [Key](#proto.Key) | [Empty](#proto.Key) |  |
| CreateSelectorMapEntry | [SelectorMapEntry](#proto.SelectorMapEntry) | [Empty](#proto.SelectorMapEntry) |  |
| FetchSelectorMapEntry | [Key](#proto.Key) | [Empty](#proto.Key) |  |
| DeleteSelectorMapEntry | [SelectorMapEntry](#proto.SelectorMapEntry) | [Empty](#proto.SelectorMapEntry) |  |
| CreateRegistrationEntry | [RegisteredEntry](#proto.RegisteredEntry) | [Empty](#proto.RegisteredEntry) |  |
| FetchRegistrationEntry | [RegisteredEntryKey](#proto.RegisteredEntryKey) | [RegisteredEntry](#proto.RegisteredEntryKey) |  |
| UpdateRegistrationEntry | [RegisteredEntry](#proto.RegisteredEntry) | [Empty](#proto.RegisteredEntry) |  |
| DeleteRegistrationEntry | [RegisteredEntryKey](#proto.RegisteredEntryKey) | [Empty](#proto.RegisteredEntryKey) |  |
| FetchGroupedRegistrationEntries | [GroupedRegistrationKey](#proto.GroupedRegistrationKey) | [RegisteredEntries](#proto.GroupedRegistrationKey) |  |
| ListAttestorEntries | [AttestorKey](#proto.AttestorKey) | [FederatedEntries](#proto.AttestorKey) |  |
| ListSelectorEntries | [SelectorKey](#proto.SelectorKey) | [FederatedEntries](#proto.SelectorKey) |  |
| ListSpiffeEntries | [Key](#proto.Key) | [FederatedEntries](#proto.Key) |  |

 



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

