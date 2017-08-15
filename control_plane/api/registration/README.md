# Protocol Documentation
<a name="top"/>

## Table of Contents


* [registration.proto](#registration.proto)
  
    * [CreateFederatedBundleRequest](#control_plane_proto.CreateFederatedBundleRequest)
  
    * [Empty](#control_plane_proto.Empty)
  
    * [FederatedBundle](#control_plane_proto.FederatedBundle)
  
    * [FederatedSpiffeID](#control_plane_proto.FederatedSpiffeID)
  
    * [ListFederatedBundlesReply](#control_plane_proto.ListFederatedBundlesReply)
  
    * [ParentID](#control_plane_proto.ParentID)
  
    * [RegisteredEntries](#control_plane_proto.RegisteredEntries)
  
    * [RegisteredEntry](#control_plane_proto.RegisteredEntry)
  
    * [RegisteredEntryID](#control_plane_proto.RegisteredEntryID)
  
    * [Selector](#control_plane_proto.Selector)
  
    * [SpiffeID](#control_plane_proto.SpiffeID)
  
    * [UpdateEntryRequest](#control_plane_proto.UpdateEntryRequest)
  
  
  
  
    * [Registration](#control_plane_proto.Registration)
  

* [Scalar Value Types](#scalar-value-types)



<a name="registration.proto"/>
<p align="right"><a href="#top">Top</a></p>

## registration.proto
The Registration API is used to register SPIFFE IDs, and the attestation logic that should be performed on a workload before those IDs can be issued.


<a name="control_plane_proto.CreateFederatedBundleRequest"/>

### CreateFederatedBundleRequest
It represents a request with a FederatedBundle to create.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federated_bundle | [FederatedBundle](#control_plane_proto.FederatedBundle) |  |  |






<a name="control_plane_proto.Empty"/>

### Empty
Represents an empty message






<a name="control_plane_proto.FederatedBundle"/>

### FederatedBundle
A CA bundle for a different Trust Domain than the one used and managed by the Control Plane.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  |  |
| federated_bundle | [bytes](#bytes) |  |  |
| ttl | [int32](#int32) |  |  |






<a name="control_plane_proto.FederatedSpiffeID"/>

### FederatedSpiffeID
A type that represents a Federated SPIFFE Id.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  |  |






<a name="control_plane_proto.ListFederatedBundlesReply"/>

### ListFederatedBundlesReply
It represents a reply with a list of FederatedBundle.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundles | [FederatedBundle](#control_plane_proto.FederatedBundle) | repeated |  |






<a name="control_plane_proto.ParentID"/>

### ParentID
A type that represents a parent Id.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  |  |






<a name="control_plane_proto.RegisteredEntries"/>

### RegisteredEntries
A list of registered entries.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entries | [RegisteredEntry](#control_plane_proto.RegisteredEntry) | repeated |  |






<a name="control_plane_proto.RegisteredEntry"/>

### RegisteredEntry
This is a curated record that the Control Plane uses to set up and manage the various registered nodes and workloads that are controlled by it.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectors | [Selector](#control_plane_proto.Selector) | repeated |  |
| parent_id | [string](#string) |  |  |
| spiffe_id | [string](#string) |  |  |
| ttl | [int32](#int32) |  |  |
| fb_spiffe_ids | [string](#string) | repeated |  |






<a name="control_plane_proto.RegisteredEntryID"/>

### RegisteredEntryID
A type that represents the id of an entry.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  |  |






<a name="control_plane_proto.Selector"/>

### Selector
A type which describes the conditions under which a registration entry is matched.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [string](#string) |  |  |
| value | [string](#string) |  |  |






<a name="control_plane_proto.SpiffeID"/>

### SpiffeID
A type that represents a SPIFFE Id.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  |  |






<a name="control_plane_proto.UpdateEntryRequest"/>

### UpdateEntryRequest
A type with the id with want to update plus values to modify.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  |  |
| entry | [RegisteredEntry](#control_plane_proto.RegisteredEntry) |  |  |





 

 

 


<a name="control_plane_proto.Registration"/>

### Registration


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| CreateEntry | [RegisteredEntry](#control_plane_proto.RegisteredEntry) | [RegisteredEntryID](#control_plane_proto.RegisteredEntry) | Creates an entry in the Registration table, used to assign SPIFFE IDs to nodes and workloads. |
| DeleteEntry | [RegisteredEntryID](#control_plane_proto.RegisteredEntryID) | [RegisteredEntry](#control_plane_proto.RegisteredEntryID) | Deletes an entry and returns the deleted entry. |
| FetchEntry | [RegisteredEntryID](#control_plane_proto.RegisteredEntryID) | [RegisteredEntry](#control_plane_proto.RegisteredEntryID) | Retrieve a specific registered entry. |
| UpdateEntry | [UpdateEntryRequest](#control_plane_proto.UpdateEntryRequest) | [RegisteredEntry](#control_plane_proto.UpdateEntryRequest) | Updates a specific registered entry. |
| ListByParentID | [ParentID](#control_plane_proto.ParentID) | [RegisteredEntries](#control_plane_proto.ParentID) | Returns all the Entries associated with the ParentID value. |
| ListBySelector | [Selector](#control_plane_proto.Selector) | [RegisteredEntries](#control_plane_proto.Selector) | Returns all the entries associated with a selector value. |
| ListBySpiffeID | [SpiffeID](#control_plane_proto.SpiffeID) | [RegisteredEntries](#control_plane_proto.SpiffeID) | Return all registration entries for which SPIFFE ID matches. |
| CreateFederatedBundle | [CreateFederatedBundleRequest](#control_plane_proto.CreateFederatedBundleRequest) | [Empty](#control_plane_proto.CreateFederatedBundleRequest) | Creates an entry in the Federated bundle table to store the mappings of Federated SPIFFE IDs and their associated CA bundle. |
| ListFederatedBundles | [Empty](#control_plane_proto.Empty) | [ListFederatedBundlesReply](#control_plane_proto.Empty) | Retrieves Federated bundles for all the Federated SPIFFE IDs. |
| UpdateFederatedBundle | [FederatedBundle](#control_plane_proto.FederatedBundle) | [Empty](#control_plane_proto.FederatedBundle) | Updates a particular Federated Bundle. Useful for rotation. |
| DeleteFederatedBundle | [FederatedSpiffeID](#control_plane_proto.FederatedSpiffeID) | [Empty](#control_plane_proto.FederatedSpiffeID) | Delete a particular Federated Bundle. Used to destroy inter-domain trust. |

 



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

