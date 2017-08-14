# Protocol Documentation
<a name="top"/>

## Table of Contents


* [common.proto](#common.proto)
  
    * [ConfigureRequest](#control_plane_proto.ConfigureRequest)
  
    * [ConfigureResponse](#control_plane_proto.ConfigureResponse)
  
    * [GetPluginInfoRequest](#control_plane_proto.GetPluginInfoRequest)
  
    * [GetPluginInfoResponse](#control_plane_proto.GetPluginInfoResponse)
  
  
  
  


* [data_store.proto](#data_store.proto)
  
    * [AttestedNodeEntry](#control_plane_proto.AttestedNodeEntry)
  
    * [CreateAttestedNodeEntryRequest](#control_plane_proto.CreateAttestedNodeEntryRequest)
  
    * [CreateAttestedNodeEntryResponse](#control_plane_proto.CreateAttestedNodeEntryResponse)
  
    * [CreateFederatedEntryRequest](#control_plane_proto.CreateFederatedEntryRequest)
  
    * [CreateFederatedEntryResponse](#control_plane_proto.CreateFederatedEntryResponse)
  
    * [CreateNodeResolverMapEntryRequest](#control_plane_proto.CreateNodeResolverMapEntryRequest)
  
    * [CreateNodeResolverMapEntryResponse](#control_plane_proto.CreateNodeResolverMapEntryResponse)
  
    * [CreateRegistrationEntryRequest](#control_plane_proto.CreateRegistrationEntryRequest)
  
    * [CreateRegistrationEntryResponse](#control_plane_proto.CreateRegistrationEntryResponse)
  
    * [DeleteAttestedNodeEntryRequest](#control_plane_proto.DeleteAttestedNodeEntryRequest)
  
    * [DeleteAttestedNodeEntryResponse](#control_plane_proto.DeleteAttestedNodeEntryResponse)
  
    * [DeleteFederatedEntryRequest](#control_plane_proto.DeleteFederatedEntryRequest)
  
    * [DeleteFederatedEntryResponse](#control_plane_proto.DeleteFederatedEntryResponse)
  
    * [DeleteNodeResolverMapEntryRequest](#control_plane_proto.DeleteNodeResolverMapEntryRequest)
  
    * [DeleteNodeResolverMapEntryResponse](#control_plane_proto.DeleteNodeResolverMapEntryResponse)
  
    * [DeleteRegistrationEntryRequest](#control_plane_proto.DeleteRegistrationEntryRequest)
  
    * [DeleteRegistrationEntryResponse](#control_plane_proto.DeleteRegistrationEntryResponse)
  
    * [FederatedBundle](#control_plane_proto.FederatedBundle)
  
    * [FetchAttestedNodeEntryRequest](#control_plane_proto.FetchAttestedNodeEntryRequest)
  
    * [FetchAttestedNodeEntryResponse](#control_plane_proto.FetchAttestedNodeEntryResponse)
  
    * [FetchNodeResolverMapEntryRequest](#control_plane_proto.FetchNodeResolverMapEntryRequest)
  
    * [FetchNodeResolverMapEntryResponse](#control_plane_proto.FetchNodeResolverMapEntryResponse)
  
    * [FetchRegistrationEntryRequest](#control_plane_proto.FetchRegistrationEntryRequest)
  
    * [FetchRegistrationEntryResponse](#control_plane_proto.FetchRegistrationEntryResponse)
  
    * [FetchStaleNodeEntriesRequest](#control_plane_proto.FetchStaleNodeEntriesRequest)
  
    * [FetchStaleNodeEntriesResponse](#control_plane_proto.FetchStaleNodeEntriesResponse)
  
    * [ListFederatedEntryRequest](#control_plane_proto.ListFederatedEntryRequest)
  
    * [ListFederatedEntryResponse](#control_plane_proto.ListFederatedEntryResponse)
  
    * [ListParentIDEntriesRequest](#control_plane_proto.ListParentIDEntriesRequest)
  
    * [ListParentIDEntriesResponse](#control_plane_proto.ListParentIDEntriesResponse)
  
    * [ListSelectorEntriesRequest](#control_plane_proto.ListSelectorEntriesRequest)
  
    * [ListSelectorEntriesResponse](#control_plane_proto.ListSelectorEntriesResponse)
  
    * [ListSpiffeEntriesRequest](#control_plane_proto.ListSpiffeEntriesRequest)
  
    * [ListSpiffeEntriesResponse](#control_plane_proto.ListSpiffeEntriesResponse)
  
    * [NodeResolverMapEntry](#control_plane_proto.NodeResolverMapEntry)
  
    * [RectifyNodeResolverMapEntriesRequest](#control_plane_proto.RectifyNodeResolverMapEntriesRequest)
  
    * [RectifyNodeResolverMapEntriesResponse](#control_plane_proto.RectifyNodeResolverMapEntriesResponse)
  
    * [RegisteredEntry](#control_plane_proto.RegisteredEntry)
  
    * [Selector](#control_plane_proto.Selector)
  
    * [UpdateAttestedNodeEntryRequest](#control_plane_proto.UpdateAttestedNodeEntryRequest)
  
    * [UpdateAttestedNodeEntryResponse](#control_plane_proto.UpdateAttestedNodeEntryResponse)
  
    * [UpdateFederatedEntryRequest](#control_plane_proto.UpdateFederatedEntryRequest)
  
    * [UpdateFederatedEntryResponse](#control_plane_proto.UpdateFederatedEntryResponse)
  
    * [UpdateRegistrationEntryRequest](#control_plane_proto.UpdateRegistrationEntryRequest)
  
    * [UpdateRegistrationEntryResponse](#control_plane_proto.UpdateRegistrationEntryResponse)
  
  
  
  
    * [DataStore](#control_plane_proto.DataStore)
  

* [Scalar Value Types](#scalar-value-types)



<a name="common.proto"/>
<p align="right"><a href="#top">Top</a></p>

## common.proto



<a name="control_plane_proto.ConfigureRequest"/>

### ConfigureRequest
Represents the plugin-specific configuration string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| configuration | [string](#string) |  | The configuration for the plugin. |






<a name="control_plane_proto.ConfigureResponse"/>

### ConfigureResponse
Represents a list of configuration problems found in the configuration string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| errorList | [string](#string) | repeated | A list of errors. |






<a name="control_plane_proto.GetPluginInfoRequest"/>

### GetPluginInfoRequest
Represents an empty request.






<a name="control_plane_proto.GetPluginInfoResponse"/>

### GetPluginInfoResponse
Represents the plugin metadata.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| category | [string](#string) |  |  |
| type | [string](#string) |  |  |
| description | [string](#string) |  |  |
| dateCreated | [string](#string) |  |  |
| location | [string](#string) |  |  |
| version | [string](#string) |  |  |
| author | [string](#string) |  |  |
| company | [string](#string) |  |  |





 

 

 

 



<a name="data_store.proto"/>
<p align="right"><a href="#top">Top</a></p>

## data_store.proto



<a name="control_plane_proto.AttestedNodeEntry"/>

### AttestedNodeEntry
Represents a single entry in AttestedNodes and stores the node&#39;s SPIFFE ID, the
type of attestation it performed, as well as the serial number and expiration date
of its node SVID.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | Spiffe ID |
| attestedDataType | [string](#string) |  | Attestation type |
| certSerialNumber | [string](#string) |  | Serial number |
| certExpirationDate | [string](#string) |  | Expiration date |






<a name="control_plane_proto.CreateAttestedNodeEntryRequest"/>

### CreateAttestedNodeEntryRequest
Represents an Attested Node entry to create


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#control_plane_proto.AttestedNodeEntry) |  | Attested node entry |






<a name="control_plane_proto.CreateAttestedNodeEntryResponse"/>

### CreateAttestedNodeEntryResponse
Represents the created Attested Node entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#control_plane_proto.AttestedNodeEntry) |  | Attested node entry |






<a name="control_plane_proto.CreateFederatedEntryRequest"/>

### CreateFederatedEntryRequest
Represents a Federated bundle


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#control_plane_proto.FederatedBundle) |  | Federated bundle |






<a name="control_plane_proto.CreateFederatedEntryResponse"/>

### CreateFederatedEntryResponse
Empty






<a name="control_plane_proto.CreateNodeResolverMapEntryRequest"/>

### CreateNodeResolverMapEntryRequest
Represents a Node resolver map entry to create


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntry | [NodeResolverMapEntry](#control_plane_proto.NodeResolverMapEntry) |  | Node resolver map entry |






<a name="control_plane_proto.CreateNodeResolverMapEntryResponse"/>

### CreateNodeResolverMapEntryResponse
Represents the created Node resolver map entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntry | [NodeResolverMapEntry](#control_plane_proto.NodeResolverMapEntry) |  | Node resolver map entry |






<a name="control_plane_proto.CreateRegistrationEntryRequest"/>

### CreateRegistrationEntryRequest
Represents a Registration entry to create


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [RegisteredEntry](#control_plane_proto.RegisteredEntry) |  | Registration entry |






<a name="control_plane_proto.CreateRegistrationEntryResponse"/>

### CreateRegistrationEntryResponse
Represents the created Registration entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryId | [string](#string) |  | Registration entry ID |






<a name="control_plane_proto.DeleteAttestedNodeEntryRequest"/>

### DeleteAttestedNodeEntryRequest
Represents the Spiffe ID of the Attested node entry to delete


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | SPIFFE ID |






<a name="control_plane_proto.DeleteAttestedNodeEntryResponse"/>

### DeleteAttestedNodeEntryResponse
Represents the deleted Attested node entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#control_plane_proto.AttestedNodeEntry) |  |  |






<a name="control_plane_proto.DeleteFederatedEntryRequest"/>

### DeleteFederatedEntryRequest
Represents the Spiffe ID of the federated bundle to delete


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundleSpiffeId | [string](#string) |  | SPIFFE ID of foreign trust domain |






<a name="control_plane_proto.DeleteFederatedEntryResponse"/>

### DeleteFederatedEntryResponse
Represents the deleted federated bundle


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#control_plane_proto.FederatedBundle) |  | Federated bundle |






<a name="control_plane_proto.DeleteNodeResolverMapEntryRequest"/>

### DeleteNodeResolverMapEntryRequest
Represents a Node resolver map entry to delete


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntry | [NodeResolverMapEntry](#control_plane_proto.NodeResolverMapEntry) |  | Node resolver map entry |






<a name="control_plane_proto.DeleteNodeResolverMapEntryResponse"/>

### DeleteNodeResolverMapEntryResponse
Represents a list of Node resolver map entries


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntryList | [NodeResolverMapEntry](#control_plane_proto.NodeResolverMapEntry) | repeated | List of Node resolver map entries |






<a name="control_plane_proto.DeleteRegistrationEntryRequest"/>

### DeleteRegistrationEntryRequest
Represents a Registration entry ID to delete


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryId | [string](#string) |  | Registration entry ID |






<a name="control_plane_proto.DeleteRegistrationEntryResponse"/>

### DeleteRegistrationEntryResponse
Represents the deleted Registration entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [RegisteredEntry](#control_plane_proto.RegisteredEntry) |  | Registration entry |






<a name="control_plane_proto.FederatedBundle"/>

### FederatedBundle
Represents the trust chain for a different trust domain, along with
a TTL describing its expiration, keyed by the SPIFFE ID of the foreign
trust domain.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundleSpiffeId | [string](#string) |  | Foreign trust domain SPIFFE ID |
| federatedTrustBundle | [bytes](#bytes) |  | Trust chain |
| ttl | [int32](#int32) |  | TTL |






<a name="control_plane_proto.FetchAttestedNodeEntryRequest"/>

### FetchAttestedNodeEntryRequest
Represents the Spiffe ID of the node entry to retrieve


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | SPIFFE ID |






<a name="control_plane_proto.FetchAttestedNodeEntryResponse"/>

### FetchAttestedNodeEntryResponse
Represents an Attested Node entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#control_plane_proto.AttestedNodeEntry) |  | Attested node entry |






<a name="control_plane_proto.FetchNodeResolverMapEntryRequest"/>

### FetchNodeResolverMapEntryRequest
Represents a Spiffe ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | SPIFFE ID |






<a name="control_plane_proto.FetchNodeResolverMapEntryResponse"/>

### FetchNodeResolverMapEntryResponse
Represents a list of Node resolver map entries for the specified Spiffe ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntryList | [NodeResolverMapEntry](#control_plane_proto.NodeResolverMapEntry) | repeated | List of Node resolver map entries |






<a name="control_plane_proto.FetchRegistrationEntryRequest"/>

### FetchRegistrationEntryRequest
Represents a Registration entry ID to fetch


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryId | [string](#string) |  | Registration entry ID |






<a name="control_plane_proto.FetchRegistrationEntryResponse"/>

### FetchRegistrationEntryResponse
Represents a Registration entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [RegisteredEntry](#control_plane_proto.RegisteredEntry) |  | Registration entry |






<a name="control_plane_proto.FetchStaleNodeEntriesRequest"/>

### FetchStaleNodeEntriesRequest
Empty






<a name="control_plane_proto.FetchStaleNodeEntriesResponse"/>

### FetchStaleNodeEntriesResponse
Represents dead nodes for which the base SVID has expired


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntryList | [AttestedNodeEntry](#control_plane_proto.AttestedNodeEntry) | repeated | List of attested node entries |






<a name="control_plane_proto.ListFederatedEntryRequest"/>

### ListFederatedEntryRequest
Empty






<a name="control_plane_proto.ListFederatedEntryResponse"/>

### ListFederatedEntryResponse
Represents a list of SPIFFE IDs of foreign trust domains


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundleSpiffeIdList | [string](#string) | repeated | SPIFFE IDs of foreign trust domains |






<a name="control_plane_proto.ListParentIDEntriesRequest"/>

### ListParentIDEntriesRequest
Represents a Parent ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| parentId | [string](#string) |  | Parent ID |






<a name="control_plane_proto.ListParentIDEntriesResponse"/>

### ListParentIDEntriesResponse
Represents a list of Registered entries with the specified Parent ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryList | [RegisteredEntry](#control_plane_proto.RegisteredEntry) | repeated | List of Registration entries |






<a name="control_plane_proto.ListSelectorEntriesRequest"/>

### ListSelectorEntriesRequest
Represents a selector


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selector | [Selector](#control_plane_proto.Selector) |  | Selector |






<a name="control_plane_proto.ListSelectorEntriesResponse"/>

### ListSelectorEntriesResponse
Represents a list of Registered entries with the specified selector


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryList | [RegisteredEntry](#control_plane_proto.RegisteredEntry) | repeated | List of Registration entries |






<a name="control_plane_proto.ListSpiffeEntriesRequest"/>

### ListSpiffeEntriesRequest
Represents a Spiffe ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeId | [string](#string) |  | Spiffe ID |






<a name="control_plane_proto.ListSpiffeEntriesResponse"/>

### ListSpiffeEntriesResponse
Represents a list of Registered entries with the specified Spiffe ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryList | [RegisteredEntry](#control_plane_proto.RegisteredEntry) | repeated | List of Registration entries |






<a name="control_plane_proto.NodeResolverMapEntry"/>

### NodeResolverMapEntry
Represents a single entry in NodeResolverMap and maps node properties to
logical attributes (i.e. an AWS instance to its ASG).


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  |  |
| selector | [Selector](#control_plane_proto.Selector) |  |  |






<a name="control_plane_proto.RectifyNodeResolverMapEntriesRequest"/>

### RectifyNodeResolverMapEntriesRequest
Represents a list of Node resolver map entries


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntryList | [NodeResolverMapEntry](#control_plane_proto.NodeResolverMapEntry) | repeated | List of Node resolver map entries |






<a name="control_plane_proto.RectifyNodeResolverMapEntriesResponse"/>

### RectifyNodeResolverMapEntriesResponse
Represents a list of Node resolver map entries


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntryList | [NodeResolverMapEntry](#control_plane_proto.NodeResolverMapEntry) | repeated | List of Node resolver map entries |






<a name="control_plane_proto.RegisteredEntry"/>

### RegisteredEntry
Represents a single Registration Entry.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectorList | [Selector](#control_plane_proto.Selector) | repeated | Array of selectors |
| spiffeId | [string](#string) |  | SPIFFE ID |
| parentId | [string](#string) |  | Attestor SPIFFE ID |
| ttl | [int32](#int32) |  | TTL |
| federatedBundleSpiffeIdList | [string](#string) | repeated | SPIFFE IDs of foreign trust domains |






<a name="control_plane_proto.Selector"/>

### Selector
Describes the conditions under which a registration entry is matched.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [string](#string) |  | Selector type |
| value | [string](#string) |  | Selector value |






<a name="control_plane_proto.UpdateAttestedNodeEntryRequest"/>

### UpdateAttestedNodeEntryRequest
Represents Attested node entry fields to update


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | Spiffe ID |
| certSerialNumber | [string](#string) |  | Serial number |
| certExpirationDate | [string](#string) |  | Expiration date |






<a name="control_plane_proto.UpdateAttestedNodeEntryResponse"/>

### UpdateAttestedNodeEntryResponse
Represents the updated Attested node entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#control_plane_proto.AttestedNodeEntry) |  | Attested node entry |






<a name="control_plane_proto.UpdateFederatedEntryRequest"/>

### UpdateFederatedEntryRequest
Represents a federated bundle to update


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#control_plane_proto.FederatedBundle) |  | Federated bundle |






<a name="control_plane_proto.UpdateFederatedEntryResponse"/>

### UpdateFederatedEntryResponse
Represents the updated federated bundle


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#control_plane_proto.FederatedBundle) |  | Federated bundle |






<a name="control_plane_proto.UpdateRegistrationEntryRequest"/>

### UpdateRegistrationEntryRequest
Represents a Registration entry to update


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryId | [string](#string) |  | Registration entry ID |
| registeredEntry | [RegisteredEntry](#control_plane_proto.RegisteredEntry) |  | Registration entry |






<a name="control_plane_proto.UpdateRegistrationEntryResponse"/>

### UpdateRegistrationEntryResponse
Represents the updated Registration entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [RegisteredEntry](#control_plane_proto.RegisteredEntry) |  | Registration entry |





 

 

 


<a name="control_plane_proto.DataStore"/>

### DataStore


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| CreateFederatedEntry | [CreateFederatedEntryRequest](#control_plane_proto.CreateFederatedEntryRequest) | [CreateFederatedEntryResponse](#control_plane_proto.CreateFederatedEntryRequest) | Creates a Federated Bundle |
| ListFederatedEntry | [ListFederatedEntryRequest](#control_plane_proto.ListFederatedEntryRequest) | [ListFederatedEntryResponse](#control_plane_proto.ListFederatedEntryRequest) | List all Federated SPIFFE IDs |
| UpdateFederatedEntry | [UpdateFederatedEntryRequest](#control_plane_proto.UpdateFederatedEntryRequest) | [UpdateFederatedEntryResponse](#control_plane_proto.UpdateFederatedEntryRequest) | Updates the specified Federated Bundle |
| DeleteFederatedEntry | [DeleteFederatedEntryRequest](#control_plane_proto.DeleteFederatedEntryRequest) | [DeleteFederatedEntryResponse](#control_plane_proto.DeleteFederatedEntryRequest) | Deletes the specified Federated Bundle |
| CreateAttestedNodeEntry | [CreateAttestedNodeEntryRequest](#control_plane_proto.CreateAttestedNodeEntryRequest) | [CreateAttestedNodeEntryResponse](#control_plane_proto.CreateAttestedNodeEntryRequest) | Creates an Attested Node Entry |
| FetchAttestedNodeEntry | [FetchAttestedNodeEntryRequest](#control_plane_proto.FetchAttestedNodeEntryRequest) | [FetchAttestedNodeEntryResponse](#control_plane_proto.FetchAttestedNodeEntryRequest) | Retrieves the Attested Node Entry |
| FetchStaleNodeEntries | [FetchStaleNodeEntriesRequest](#control_plane_proto.FetchStaleNodeEntriesRequest) | [FetchStaleNodeEntriesResponse](#control_plane_proto.FetchStaleNodeEntriesRequest) | Retrieves dead nodes for which the base SVID has expired |
| UpdateAttestedNodeEntry | [UpdateAttestedNodeEntryRequest](#control_plane_proto.UpdateAttestedNodeEntryRequest) | [UpdateAttestedNodeEntryResponse](#control_plane_proto.UpdateAttestedNodeEntryRequest) | Updates the Attested Node Entry |
| DeleteAttestedNodeEntry | [DeleteAttestedNodeEntryRequest](#control_plane_proto.DeleteAttestedNodeEntryRequest) | [DeleteAttestedNodeEntryResponse](#control_plane_proto.DeleteAttestedNodeEntryRequest) | Deletes the Attested Node Entry |
| CreateNodeResolverMapEntry | [CreateNodeResolverMapEntryRequest](#control_plane_proto.CreateNodeResolverMapEntryRequest) | [CreateNodeResolverMapEntryResponse](#control_plane_proto.CreateNodeResolverMapEntryRequest) | Creates a Node resolver map Entry |
| FetchNodeResolverMapEntry | [FetchNodeResolverMapEntryRequest](#control_plane_proto.FetchNodeResolverMapEntryRequest) | [FetchNodeResolverMapEntryResponse](#control_plane_proto.FetchNodeResolverMapEntryRequest) | Retrieves all Node Resolver Map Entry for the specific base SPIFFEID |
| DeleteNodeResolverMapEntry | [DeleteNodeResolverMapEntryRequest](#control_plane_proto.DeleteNodeResolverMapEntryRequest) | [DeleteNodeResolverMapEntryResponse](#control_plane_proto.DeleteNodeResolverMapEntryRequest) | Deletes all Node Resolver Map Entry for the specific base SPIFFEID |
| RectifyNodeResolverMapEntries | [RectifyNodeResolverMapEntriesRequest](#control_plane_proto.RectifyNodeResolverMapEntriesRequest) | [RectifyNodeResolverMapEntriesResponse](#control_plane_proto.RectifyNodeResolverMapEntriesRequest) | Used for rectifying updated node resolutions |
| CreateRegistrationEntry | [CreateRegistrationEntryRequest](#control_plane_proto.CreateRegistrationEntryRequest) | [CreateRegistrationEntryResponse](#control_plane_proto.CreateRegistrationEntryRequest) | Creates a Registered Entry |
| FetchRegistrationEntry | [FetchRegistrationEntryRequest](#control_plane_proto.FetchRegistrationEntryRequest) | [FetchRegistrationEntryResponse](#control_plane_proto.FetchRegistrationEntryRequest) | Retrieve a specific registered entry |
| UpdateRegistrationEntry | [UpdateRegistrationEntryRequest](#control_plane_proto.UpdateRegistrationEntryRequest) | [UpdateRegistrationEntryResponse](#control_plane_proto.UpdateRegistrationEntryRequest) | Updates a specific registered entry |
| DeleteRegistrationEntry | [DeleteRegistrationEntryRequest](#control_plane_proto.DeleteRegistrationEntryRequest) | [DeleteRegistrationEntryResponse](#control_plane_proto.DeleteRegistrationEntryRequest) | Deletes a specific registered entry |
| ListParentIDEntries | [ListParentIDEntriesRequest](#control_plane_proto.ListParentIDEntriesRequest) | [ListParentIDEntriesResponse](#control_plane_proto.ListParentIDEntriesRequest) | Retrieves all the  registered entry with the same ParentID |
| ListSelectorEntries | [ListSelectorEntriesRequest](#control_plane_proto.ListSelectorEntriesRequest) | [ListSelectorEntriesResponse](#control_plane_proto.ListSelectorEntriesRequest) | Retrieves all the  registered entry with the same Selector |
| ListSpiffeEntries | [ListSpiffeEntriesRequest](#control_plane_proto.ListSpiffeEntriesRequest) | [ListSpiffeEntriesResponse](#control_plane_proto.ListSpiffeEntriesRequest) | Retrieves all the  registered entry with the same SpiffeId |
| Configure | [ConfigureRequest](#control_plane_proto.ConfigureRequest) | [ConfigureResponse](#control_plane_proto.ConfigureRequest) | Applies the plugin configuration |
| GetPluginInfo | [GetPluginInfoRequest](#control_plane_proto.GetPluginInfoRequest) | [GetPluginInfoResponse](#control_plane_proto.GetPluginInfoRequest) | Returns the version and related metadata of the installed plugin |

 



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

