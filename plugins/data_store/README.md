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
  
    * [CreateAttestedNodeEntryRequest](#proto.CreateAttestedNodeEntryRequest)
  
    * [CreateAttestedNodeEntryResponse](#proto.CreateAttestedNodeEntryResponse)
  
    * [CreateFederatedEntryRequest](#proto.CreateFederatedEntryRequest)
  
    * [CreateFederatedEntryResponse](#proto.CreateFederatedEntryResponse)
  
    * [CreateNodeResolverMapEntryRequest](#proto.CreateNodeResolverMapEntryRequest)
  
    * [CreateNodeResolverMapEntryResponse](#proto.CreateNodeResolverMapEntryResponse)
  
    * [CreateRegistrationEntryRequest](#proto.CreateRegistrationEntryRequest)
  
    * [CreateRegistrationEntryResponse](#proto.CreateRegistrationEntryResponse)
  
    * [DeleteAttestedNodeEntryRequest](#proto.DeleteAttestedNodeEntryRequest)
  
    * [DeleteAttestedNodeEntryResponse](#proto.DeleteAttestedNodeEntryResponse)
  
    * [DeleteFederatedEntryRequest](#proto.DeleteFederatedEntryRequest)
  
    * [DeleteFederatedEntryResponse](#proto.DeleteFederatedEntryResponse)
  
    * [DeleteNodeResolverMapEntryRequest](#proto.DeleteNodeResolverMapEntryRequest)
  
    * [DeleteNodeResolverMapEntryResponse](#proto.DeleteNodeResolverMapEntryResponse)
  
    * [DeleteRegistrationEntryRequest](#proto.DeleteRegistrationEntryRequest)
  
    * [DeleteRegistrationEntryResponse](#proto.DeleteRegistrationEntryResponse)
  
    * [FederatedBundle](#proto.FederatedBundle)
  
    * [FetchAttestedNodeEntryRequest](#proto.FetchAttestedNodeEntryRequest)
  
    * [FetchAttestedNodeEntryResponse](#proto.FetchAttestedNodeEntryResponse)
  
    * [FetchNodeResolverMapEntryRequest](#proto.FetchNodeResolverMapEntryRequest)
  
    * [FetchNodeResolverMapEntryResponse](#proto.FetchNodeResolverMapEntryResponse)
  
    * [FetchRegistrationEntryRequest](#proto.FetchRegistrationEntryRequest)
  
    * [FetchRegistrationEntryResponse](#proto.FetchRegistrationEntryResponse)
  
    * [FetchStaleNodeEntriesRequest](#proto.FetchStaleNodeEntriesRequest)
  
    * [FetchStaleNodeEntriesResponse](#proto.FetchStaleNodeEntriesResponse)
  
    * [ListFederatedEntryRequest](#proto.ListFederatedEntryRequest)
  
    * [ListFederatedEntryResponse](#proto.ListFederatedEntryResponse)
  
    * [ListParentIDEntriesRequest](#proto.ListParentIDEntriesRequest)
  
    * [ListParentIDEntriesResponse](#proto.ListParentIDEntriesResponse)
  
    * [ListSelectorEntriesRequest](#proto.ListSelectorEntriesRequest)
  
    * [ListSelectorEntriesResponse](#proto.ListSelectorEntriesResponse)
  
    * [ListSpiffeEntriesRequest](#proto.ListSpiffeEntriesRequest)
  
    * [ListSpiffeEntriesResponse](#proto.ListSpiffeEntriesResponse)
  
    * [NodeResolverMapEntry](#proto.NodeResolverMapEntry)
  
    * [RectifyNodeResolverMapEntriesRequest](#proto.RectifyNodeResolverMapEntriesRequest)
  
    * [RectifyNodeResolverMapEntriesResponse](#proto.RectifyNodeResolverMapEntriesResponse)
  
    * [RegisteredEntry](#proto.RegisteredEntry)
  
    * [Selector](#proto.Selector)
  
    * [UpdateAttestedNodeEntryRequest](#proto.UpdateAttestedNodeEntryRequest)
  
    * [UpdateAttestedNodeEntryResponse](#proto.UpdateAttestedNodeEntryResponse)
  
    * [UpdateFederatedEntryRequest](#proto.UpdateFederatedEntryRequest)
  
    * [UpdateFederatedEntryResponse](#proto.UpdateFederatedEntryResponse)
  
    * [UpdateRegistrationEntryRequest](#proto.UpdateRegistrationEntryRequest)
  
    * [UpdateRegistrationEntryResponse](#proto.UpdateRegistrationEntryResponse)
  
  
  
  
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
Represents a single entry in AttestedNodes and stores the node&#39;s SPIFFE ID, the
type of attestation it performed, as well as the serial number and expiration date
of its node SVID.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | Spiffe ID |
| attestedDataType | [string](#string) |  | Attestation type |
| certSerialNumber | [string](#string) |  | Serial number |
| certExpirationDate | [string](#string) |  | Expiration date |






<a name="proto.CreateAttestedNodeEntryRequest"/>

### CreateAttestedNodeEntryRequest
Represents an Attested Node entry to create


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#proto.AttestedNodeEntry) |  | Attested node entry |






<a name="proto.CreateAttestedNodeEntryResponse"/>

### CreateAttestedNodeEntryResponse
Represents the created Attested Node entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#proto.AttestedNodeEntry) |  | Attested node entry |






<a name="proto.CreateFederatedEntryRequest"/>

### CreateFederatedEntryRequest
Represents a Federated bundle


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#proto.FederatedBundle) |  | Federated bundle |






<a name="proto.CreateFederatedEntryResponse"/>

### CreateFederatedEntryResponse
Empty






<a name="proto.CreateNodeResolverMapEntryRequest"/>

### CreateNodeResolverMapEntryRequest
Represents a Node resolver map entry to create


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntry | [NodeResolverMapEntry](#proto.NodeResolverMapEntry) |  | Node resolver map entry |






<a name="proto.CreateNodeResolverMapEntryResponse"/>

### CreateNodeResolverMapEntryResponse
Represents the created Node resolver map entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntry | [NodeResolverMapEntry](#proto.NodeResolverMapEntry) |  | Node resolver map entry |






<a name="proto.CreateRegistrationEntryRequest"/>

### CreateRegistrationEntryRequest
Represents a Registration entry to create


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [RegisteredEntry](#proto.RegisteredEntry) |  | Registration entry |






<a name="proto.CreateRegistrationEntryResponse"/>

### CreateRegistrationEntryResponse
Represents the created Registration entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryId | [string](#string) |  | Registration entry ID |






<a name="proto.DeleteAttestedNodeEntryRequest"/>

### DeleteAttestedNodeEntryRequest
Represents the Spiffe ID of the Attested node entry to delete


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | SPIFFE ID |






<a name="proto.DeleteAttestedNodeEntryResponse"/>

### DeleteAttestedNodeEntryResponse
Represents the deleted Attested node entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#proto.AttestedNodeEntry) |  |  |






<a name="proto.DeleteFederatedEntryRequest"/>

### DeleteFederatedEntryRequest
Represents the Spiffe ID of the federated bundle to delete


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundleSpiffeId | [string](#string) |  | SPIFFE ID of foreign trust domain |






<a name="proto.DeleteFederatedEntryResponse"/>

### DeleteFederatedEntryResponse
Represents the deleted federated bundle


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#proto.FederatedBundle) |  | Federated bundle |






<a name="proto.DeleteNodeResolverMapEntryRequest"/>

### DeleteNodeResolverMapEntryRequest
Represents a Node resolver map entry to delete


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntry | [NodeResolverMapEntry](#proto.NodeResolverMapEntry) |  | Node resolver map entry |






<a name="proto.DeleteNodeResolverMapEntryResponse"/>

### DeleteNodeResolverMapEntryResponse
Represents a list of Node resolver map entries


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntryList | [NodeResolverMapEntry](#proto.NodeResolverMapEntry) | repeated | List of Node resolver map entries |






<a name="proto.DeleteRegistrationEntryRequest"/>

### DeleteRegistrationEntryRequest
Represents a Registration entry ID to delete


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryId | [string](#string) |  | Registration entry ID |






<a name="proto.DeleteRegistrationEntryResponse"/>

### DeleteRegistrationEntryResponse
Represents the deleted Registration entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [RegisteredEntry](#proto.RegisteredEntry) |  | Registration entry |






<a name="proto.FederatedBundle"/>

### FederatedBundle
Represents the trust chain for a different trust domain, along with
a TTL describing its expiration, keyed by the SPIFFE ID of the foreign
trust domain.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundleSpiffeId | [string](#string) |  | Foreign trust domain SPIFFE ID |
| federatedTrustBundle | [bytes](#bytes) |  | Trust chain |
| ttl | [int32](#int32) |  | TTL |






<a name="proto.FetchAttestedNodeEntryRequest"/>

### FetchAttestedNodeEntryRequest
Represents the Spiffe ID of the node entry to retrieve


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | SPIFFE ID |






<a name="proto.FetchAttestedNodeEntryResponse"/>

### FetchAttestedNodeEntryResponse
Represents an Attested Node entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#proto.AttestedNodeEntry) |  | Attested node entry |






<a name="proto.FetchNodeResolverMapEntryRequest"/>

### FetchNodeResolverMapEntryRequest
Represents a Spiffe ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | SPIFFE ID |






<a name="proto.FetchNodeResolverMapEntryResponse"/>

### FetchNodeResolverMapEntryResponse
Represents a list of Node resolver map entries for the specified Spiffe ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntryList | [NodeResolverMapEntry](#proto.NodeResolverMapEntry) | repeated | List of Node resolver map entries |






<a name="proto.FetchRegistrationEntryRequest"/>

### FetchRegistrationEntryRequest
Represents a Registration entry ID to fetch


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryId | [string](#string) |  | Registration entry ID |






<a name="proto.FetchRegistrationEntryResponse"/>

### FetchRegistrationEntryResponse
Represents a Registration entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [RegisteredEntry](#proto.RegisteredEntry) |  | Registration entry |






<a name="proto.FetchStaleNodeEntriesRequest"/>

### FetchStaleNodeEntriesRequest
Empty






<a name="proto.FetchStaleNodeEntriesResponse"/>

### FetchStaleNodeEntriesResponse
Represents dead nodes for which the base SVID has expired


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntryList | [AttestedNodeEntry](#proto.AttestedNodeEntry) | repeated | List of attested node entries |






<a name="proto.ListFederatedEntryRequest"/>

### ListFederatedEntryRequest
Empty






<a name="proto.ListFederatedEntryResponse"/>

### ListFederatedEntryResponse
Represents a list of SPIFFE IDs of foreign trust domains


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundleSpiffeIdList | [string](#string) | repeated | SPIFFE IDs of foreign trust domains |






<a name="proto.ListParentIDEntriesRequest"/>

### ListParentIDEntriesRequest
Represents a Parent ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| parentId | [string](#string) |  | Parent ID |






<a name="proto.ListParentIDEntriesResponse"/>

### ListParentIDEntriesResponse
Represents a list of Registered entries with the specified Parent ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryList | [RegisteredEntry](#proto.RegisteredEntry) | repeated | List of Registration entries |






<a name="proto.ListSelectorEntriesRequest"/>

### ListSelectorEntriesRequest
Represents a selector


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selector | [Selector](#proto.Selector) |  | Selector |






<a name="proto.ListSelectorEntriesResponse"/>

### ListSelectorEntriesResponse
Represents a list of Registered entries with the specified selector


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryList | [RegisteredEntry](#proto.RegisteredEntry) | repeated | List of Registration entries |






<a name="proto.ListSpiffeEntriesRequest"/>

### ListSpiffeEntriesRequest
Represents a Spiffe ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeId | [string](#string) |  | Spiffe ID |






<a name="proto.ListSpiffeEntriesResponse"/>

### ListSpiffeEntriesResponse
Represents a list of Registered entries with the specified Spiffe ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryList | [RegisteredEntry](#proto.RegisteredEntry) | repeated | List of Registration entries |






<a name="proto.NodeResolverMapEntry"/>

### NodeResolverMapEntry
Represents a single entry in NodeResolverMap and maps node properties to
logical attributes (i.e. an AWS instance to its ASG).


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  |  |
| selector | [Selector](#proto.Selector) |  |  |






<a name="proto.RectifyNodeResolverMapEntriesRequest"/>

### RectifyNodeResolverMapEntriesRequest
Represents a list of Node resolver map entries


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntryList | [NodeResolverMapEntry](#proto.NodeResolverMapEntry) | repeated | List of Node resolver map entries |






<a name="proto.RectifyNodeResolverMapEntriesResponse"/>

### RectifyNodeResolverMapEntriesResponse
Represents a list of Node resolver map entries


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntryList | [NodeResolverMapEntry](#proto.NodeResolverMapEntry) | repeated | List of Node resolver map entries |






<a name="proto.RegisteredEntry"/>

### RegisteredEntry
Represents a single Registration Entry.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectorList | [Selector](#proto.Selector) | repeated | Array of selectors |
| spiffeId | [string](#string) |  | SPIFFE ID |
| parentId | [string](#string) |  | Attestor SPIFFE ID |
| ttl | [int32](#int32) |  | TTL |
| federatedBundleSpiffeIdList | [string](#string) | repeated | SPIFFE IDs of foreign trust domains |






<a name="proto.Selector"/>

### Selector
Describes the conditions under which a registration entry is matched.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [string](#string) |  | Selector type |
| value | [string](#string) |  | Selector value |






<a name="proto.UpdateAttestedNodeEntryRequest"/>

### UpdateAttestedNodeEntryRequest
Represents Attested node entry fields to update


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | Spiffe ID |
| certSerialNumber | [string](#string) |  | Serial number |
| certExpirationDate | [string](#string) |  | Expiration date |






<a name="proto.UpdateAttestedNodeEntryResponse"/>

### UpdateAttestedNodeEntryResponse
Represents the updated Attested node entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#proto.AttestedNodeEntry) |  | Attested node entry |






<a name="proto.UpdateFederatedEntryRequest"/>

### UpdateFederatedEntryRequest
Represents a federated bundle to update


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#proto.FederatedBundle) |  | Federated bundle |






<a name="proto.UpdateFederatedEntryResponse"/>

### UpdateFederatedEntryResponse
Represents the updated federated bundle


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#proto.FederatedBundle) |  | Federated bundle |






<a name="proto.UpdateRegistrationEntryRequest"/>

### UpdateRegistrationEntryRequest
Represents a Registration entry to update


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryId | [string](#string) |  | Registration entry ID |
| registeredEntry | [RegisteredEntry](#proto.RegisteredEntry) |  | Registration entry |






<a name="proto.UpdateRegistrationEntryResponse"/>

### UpdateRegistrationEntryResponse
Represents the updated Registration entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [RegisteredEntry](#proto.RegisteredEntry) |  | Registration entry |





 

 

 


<a name="proto.DataStore"/>

### DataStore


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| CreateFederatedEntry | [CreateFederatedEntryRequest](#proto.CreateFederatedEntryRequest) | [CreateFederatedEntryResponse](#proto.CreateFederatedEntryRequest) | Creates a Federated Bundle |
| ListFederatedEntry | [ListFederatedEntryRequest](#proto.ListFederatedEntryRequest) | [ListFederatedEntryResponse](#proto.ListFederatedEntryRequest) | List all Federated SPIFFE IDs |
| UpdateFederatedEntry | [UpdateFederatedEntryRequest](#proto.UpdateFederatedEntryRequest) | [UpdateFederatedEntryResponse](#proto.UpdateFederatedEntryRequest) | Updates the specified Federated Bundle |
| DeleteFederatedEntry | [DeleteFederatedEntryRequest](#proto.DeleteFederatedEntryRequest) | [DeleteFederatedEntryResponse](#proto.DeleteFederatedEntryRequest) | Deletes the specified Federated Bundle |
| CreateAttestedNodeEntry | [CreateAttestedNodeEntryRequest](#proto.CreateAttestedNodeEntryRequest) | [CreateAttestedNodeEntryResponse](#proto.CreateAttestedNodeEntryRequest) | Creates an Attested Node Entry |
| FetchAttestedNodeEntry | [FetchAttestedNodeEntryRequest](#proto.FetchAttestedNodeEntryRequest) | [FetchAttestedNodeEntryResponse](#proto.FetchAttestedNodeEntryRequest) | Retrieves the Attested Node Entry |
| FetchStaleNodeEntries | [FetchStaleNodeEntriesRequest](#proto.FetchStaleNodeEntriesRequest) | [FetchStaleNodeEntriesResponse](#proto.FetchStaleNodeEntriesRequest) | Retrieves dead nodes for which the base SVID has expired |
| UpdateAttestedNodeEntry | [UpdateAttestedNodeEntryRequest](#proto.UpdateAttestedNodeEntryRequest) | [UpdateAttestedNodeEntryResponse](#proto.UpdateAttestedNodeEntryRequest) | Updates the Attested Node Entry |
| DeleteAttestedNodeEntry | [DeleteAttestedNodeEntryRequest](#proto.DeleteAttestedNodeEntryRequest) | [DeleteAttestedNodeEntryResponse](#proto.DeleteAttestedNodeEntryRequest) | Deletes the Attested Node Entry |
| CreateNodeResolverMapEntry | [CreateNodeResolverMapEntryRequest](#proto.CreateNodeResolverMapEntryRequest) | [CreateNodeResolverMapEntryResponse](#proto.CreateNodeResolverMapEntryRequest) | Creates a Node resolver map Entry |
| FetchNodeResolverMapEntry | [FetchNodeResolverMapEntryRequest](#proto.FetchNodeResolverMapEntryRequest) | [FetchNodeResolverMapEntryResponse](#proto.FetchNodeResolverMapEntryRequest) | Retrieves all Node Resolver Map Entry for the specific base SPIFFEID |
| DeleteNodeResolverMapEntry | [DeleteNodeResolverMapEntryRequest](#proto.DeleteNodeResolverMapEntryRequest) | [DeleteNodeResolverMapEntryResponse](#proto.DeleteNodeResolverMapEntryRequest) | Deletes all Node Resolver Map Entry for the specific base SPIFFEID |
| RectifyNodeResolverMapEntries | [RectifyNodeResolverMapEntriesRequest](#proto.RectifyNodeResolverMapEntriesRequest) | [RectifyNodeResolverMapEntriesResponse](#proto.RectifyNodeResolverMapEntriesRequest) | Used for rectifying updated node resolutions |
| CreateRegistrationEntry | [CreateRegistrationEntryRequest](#proto.CreateRegistrationEntryRequest) | [CreateRegistrationEntryResponse](#proto.CreateRegistrationEntryRequest) | Creates a Registered Entry |
| FetchRegistrationEntry | [FetchRegistrationEntryRequest](#proto.FetchRegistrationEntryRequest) | [FetchRegistrationEntryResponse](#proto.FetchRegistrationEntryRequest) | Retrieve a specific registered entry |
| UpdateRegistrationEntry | [UpdateRegistrationEntryRequest](#proto.UpdateRegistrationEntryRequest) | [UpdateRegistrationEntryResponse](#proto.UpdateRegistrationEntryRequest) | Updates a specific registered entry |
| DeleteRegistrationEntry | [DeleteRegistrationEntryRequest](#proto.DeleteRegistrationEntryRequest) | [DeleteRegistrationEntryResponse](#proto.DeleteRegistrationEntryRequest) | Deletes a specific registered entry |
| ListParentIDEntries | [ListParentIDEntriesRequest](#proto.ListParentIDEntriesRequest) | [ListParentIDEntriesResponse](#proto.ListParentIDEntriesRequest) | Retrieves all the  registered entry with the same ParentID |
| ListSelectorEntries | [ListSelectorEntriesRequest](#proto.ListSelectorEntriesRequest) | [ListSelectorEntriesResponse](#proto.ListSelectorEntriesRequest) | Retrieves all the  registered entry with the same Selector |
| ListSpiffeEntries | [ListSpiffeEntriesRequest](#proto.ListSpiffeEntriesRequest) | [ListSpiffeEntriesResponse](#proto.ListSpiffeEntriesRequest) | Retrieves all the  registered entry with the same SpiffeId |
| Configure | [ConfigureRequest](#proto.ConfigureRequest) | [ConfigureResponse](#proto.ConfigureRequest) | Applies the plugin configuration |
| GetPluginInfo | [GetPluginInfoRequest](#proto.GetPluginInfoRequest) | [GetPluginInfoResponse](#proto.GetPluginInfoRequest) | Returns the version and related metadata of the installed plugin |

 



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

