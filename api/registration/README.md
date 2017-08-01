# Protocol Documentation
<a name="top"/>

## Table of Contents
* [registration.proto](#registration.proto)
 * [CreateEntryRequest](#pb.CreateEntryRequest)
 * [CreateFederatedBundleRequest](#pb.CreateFederatedBundleRequest)
 * [DeleteEntryRequest](#pb.DeleteEntryRequest)
 * [DeleteEntryResponse](#pb.DeleteEntryResponse)
 * [DeleteFederatedBundleRequest](#pb.DeleteFederatedBundleRequest)
 * [FederatedBundle](#pb.FederatedBundle)
 * [ListByParentIDRequest](#pb.ListByParentIDRequest)
 * [ListByParentIDResponse](#pb.ListByParentIDResponse)
 * [ListBySelectorRequest](#pb.ListBySelectorRequest)
 * [ListBySelectorResponse](#pb.ListBySelectorResponse)
 * [ListBySpiffeIDRequest](#pb.ListBySpiffeIDRequest)
 * [ListBySpiffeIDResponse](#pb.ListBySpiffeIDResponse)
 * [ListFederatedBundlesResponse](#pb.ListFederatedBundlesResponse)
 * [RegisteredEntry](#pb.RegisteredEntry)
 * [UpdateFederatedBundleRequest](#pb.UpdateFederatedBundleRequest)
 * [registration](#pb.registration)
* [Scalar Value Types](#scalar-value-types)

<a name="registration.proto"/>
<p align="right"><a href="#top">Top</a></p>

## registration.proto

The Registration API is used to register SPIFFE IDs, and the attestation logic
that should be performed on a workload before those IDs can be issued.

<a name="pb.CreateEntryRequest"/>
### CreateEntryRequest

represents an entity to be created

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [RegisteredEntry](#pb.RegisteredEntry) | optional |  |


<a name="pb.CreateFederatedBundleRequest"/>
### CreateFederatedBundleRequest

represents a federated bundle to be added

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#pb.FederatedBundle) | optional |  |


<a name="pb.DeleteEntryRequest"/>
### DeleteEntryRequest

represents the criteria that will be used to delete entries

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectorType | [string](#string) | optional |  |
| selector | [string](#string) | optional |  |


<a name="pb.DeleteEntryResponse"/>
### DeleteEntryResponse

represents the entities deleted

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryList | [RegisteredEntry](#pb.RegisteredEntry) | repeated |  |


<a name="pb.DeleteFederatedBundleRequest"/>
### DeleteFederatedBundleRequest

represents a federated bundle to be deleted

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federateBundleSpiffeId | [string](#string) | optional |  |


<a name="pb.FederatedBundle"/>
### FederatedBundle

A CA bundle for a different Trust Domain than the one used and managed by the Control Plane.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federateBundleSpiffeId | [string](#string) | optional |  |
| federateBundle | [bytes](#bytes) | optional |  |
| ttl | [int32](#int32) | optional |  |


<a name="pb.ListByParentIDRequest"/>
### ListByParentIDRequest

represents a ParentID whose children entities will be listed

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| parentID | [string](#string) | optional |  |


<a name="pb.ListByParentIDResponse"/>
### ListByParentIDResponse

represents a list of entities associated with a given ParentID

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryList | [RegisteredEntry](#pb.RegisteredEntry) | repeated |  |


<a name="pb.ListBySelectorRequest"/>
### ListBySelectorRequest

represents a selector and type to be used as the criteria to list entities

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectorType | [string](#string) | optional |  |
| selector | [string](#string) | optional |  |


<a name="pb.ListBySelectorResponse"/>
### ListBySelectorResponse

represents a list of entities associated with a given selector and type

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryList | [RegisteredEntry](#pb.RegisteredEntry) | repeated |  |


<a name="pb.ListBySpiffeIDRequest"/>
### ListBySpiffeIDRequest

represents a Spiffe ID to be used as the criteria to list entities

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeId | [string](#string) | optional |  |


<a name="pb.ListBySpiffeIDResponse"/>
### ListBySpiffeIDResponse

represents a list of entities associated with a given Spiffe ID

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryList | [RegisteredEntry](#pb.RegisteredEntry) | repeated |  |


<a name="pb.ListFederatedBundlesResponse"/>
### ListFederatedBundlesResponse

represents all the federated bundles

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundleList | [FederatedBundle](#pb.FederatedBundle) | repeated |  |


<a name="pb.RegisteredEntry"/>
### RegisteredEntry

This is a curated record that the Control Plane uses to set up and manage
the various registered nodes and workloads that are controlled by it.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectorType | [string](#string) | optional |  |
| selector | [string](#string) | optional |  |
| parentID | [string](#string) | optional |  |
| spiffeId | [string](#string) | optional |  |
| ttl | [int32](#int32) | optional |  |
| federateBundleSpiffeIdList | [string](#string) | repeated |  |


<a name="pb.UpdateFederatedBundleRequest"/>
### UpdateFederatedBundleRequest

represents a federated bundle to be updated

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#pb.FederatedBundle) | optional |  |





<a name="pb.registration"/>
### registration


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| CreateEntry | [CreateEntryRequest](#pb.CreateEntryRequest) | [CreateEntryResponse](#pb.CreateEntryResponse) | Creates an entry in the Registration table, used to assign SPIFFE IDs to nodes and workloads |
| DeleteEntry | [DeleteEntryRequest](#pb.DeleteEntryRequest) | [DeleteEntryResponse](#pb.DeleteEntryResponse) | Deletes a set of entries that match a given criteria |
| ListByParentID | [ListByParentIDRequest](#pb.ListByParentIDRequest) | [ListByParentIDResponse](#pb.ListByParentIDResponse) | Returns all the Entries associated with the ParentID value |
| ListBySelector | [ListBySelectorRequest](#pb.ListBySelectorRequest) | [ListBySelectorResponse](#pb.ListBySelectorResponse) | Returns all the entries associated with a selector value |
| ListBySpiffeID | [ListBySpiffeIDRequest](#pb.ListBySpiffeIDRequest) | [ListBySpiffeIDResponse](#pb.ListBySpiffeIDResponse) | Return all registration entries for which SPIFFE ID matches |
| CreateFederatedBundle | [CreateFederatedBundleRequest](#pb.CreateFederatedBundleRequest) | [CreateFederatedBundleResponse](#pb.CreateFederatedBundleResponse) | Creates an entry in the Federated bundle table to store the mappings of Federated SPIFFEIds and their associated CA bundle |
| ListFederatedBundles | [ListFederatedBundlesRequest](#pb.ListFederatedBundlesRequest) | [ListFederatedBundlesResponse](#pb.ListFederatedBundlesResponse) | Retrieve Federated bundles for all the Federated SPIFFEIds |
| UpdateFederatedBundle | [UpdateFederatedBundleRequest](#pb.UpdateFederatedBundleRequest) | [UpdateFederatedBundleResponse](#pb.UpdateFederatedBundleResponse) | Updates a particular Federated Bundle. Useful for rotation. |
| DeleteFederatedBundle | [DeleteFederatedBundleRequest](#pb.DeleteFederatedBundleRequest) | [DeleteFederatedBundleResponse](#pb.DeleteFederatedBundleResponse) | Delete a particular Federated Bundle. Used to destroy inter-domain trust. |



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
