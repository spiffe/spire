# Protocol Documentation
<a name="top"/>

## Table of Contents


* [common.proto](#common.proto)
  
    * [ConfigureRequest](#sri_proto.ConfigureRequest)
  
    * [ConfigureResponse](#sri_proto.ConfigureResponse)
  
    * [GetPluginInfoRequest](#sri_proto.GetPluginInfoRequest)
  
    * [GetPluginInfoResponse](#sri_proto.GetPluginInfoResponse)
  
  
  
  


* [data_store.proto](#data_store.proto)
  
    * [AttestedNodeEntry](#sri_proto.AttestedNodeEntry)
  
    * [CreateAttestedNodeEntryRequest](#sri_proto.CreateAttestedNodeEntryRequest)
  
    * [CreateAttestedNodeEntryResponse](#sri_proto.CreateAttestedNodeEntryResponse)
  
    * [CreateFederatedEntryRequest](#sri_proto.CreateFederatedEntryRequest)
  
    * [CreateFederatedEntryResponse](#sri_proto.CreateFederatedEntryResponse)
  
    * [CreateNodeResolverMapEntryRequest](#sri_proto.CreateNodeResolverMapEntryRequest)
  
    * [CreateNodeResolverMapEntryResponse](#sri_proto.CreateNodeResolverMapEntryResponse)
  
    * [CreateRegistrationEntryRequest](#sri_proto.CreateRegistrationEntryRequest)
  
    * [CreateRegistrationEntryResponse](#sri_proto.CreateRegistrationEntryResponse)
  
    * [DeleteAttestedNodeEntryRequest](#sri_proto.DeleteAttestedNodeEntryRequest)
  
    * [DeleteAttestedNodeEntryResponse](#sri_proto.DeleteAttestedNodeEntryResponse)
  
    * [DeleteFederatedEntryRequest](#sri_proto.DeleteFederatedEntryRequest)
  
    * [DeleteFederatedEntryResponse](#sri_proto.DeleteFederatedEntryResponse)
  
    * [DeleteNodeResolverMapEntryRequest](#sri_proto.DeleteNodeResolverMapEntryRequest)
  
    * [DeleteNodeResolverMapEntryResponse](#sri_proto.DeleteNodeResolverMapEntryResponse)
  
    * [DeleteRegistrationEntryRequest](#sri_proto.DeleteRegistrationEntryRequest)
  
    * [DeleteRegistrationEntryResponse](#sri_proto.DeleteRegistrationEntryResponse)
  
    * [FederatedBundle](#sri_proto.FederatedBundle)
  
    * [FetchAttestedNodeEntryRequest](#sri_proto.FetchAttestedNodeEntryRequest)
  
    * [FetchAttestedNodeEntryResponse](#sri_proto.FetchAttestedNodeEntryResponse)
  
    * [FetchNodeResolverMapEntryRequest](#sri_proto.FetchNodeResolverMapEntryRequest)
  
    * [FetchNodeResolverMapEntryResponse](#sri_proto.FetchNodeResolverMapEntryResponse)
  
    * [FetchRegistrationEntryRequest](#sri_proto.FetchRegistrationEntryRequest)
  
    * [FetchRegistrationEntryResponse](#sri_proto.FetchRegistrationEntryResponse)
  
    * [FetchStaleNodeEntriesRequest](#sri_proto.FetchStaleNodeEntriesRequest)
  
    * [FetchStaleNodeEntriesResponse](#sri_proto.FetchStaleNodeEntriesResponse)
  
    * [ListFederatedEntryRequest](#sri_proto.ListFederatedEntryRequest)
  
    * [ListFederatedEntryResponse](#sri_proto.ListFederatedEntryResponse)
  
    * [ListParentIDEntriesRequest](#sri_proto.ListParentIDEntriesRequest)
  
    * [ListParentIDEntriesResponse](#sri_proto.ListParentIDEntriesResponse)
  
    * [ListSelectorEntriesRequest](#sri_proto.ListSelectorEntriesRequest)
  
    * [ListSelectorEntriesResponse](#sri_proto.ListSelectorEntriesResponse)
  
    * [ListSpiffeEntriesRequest](#sri_proto.ListSpiffeEntriesRequest)
  
    * [ListSpiffeEntriesResponse](#sri_proto.ListSpiffeEntriesResponse)
  
    * [NodeResolverMapEntry](#sri_proto.NodeResolverMapEntry)
  
    * [RectifyNodeResolverMapEntriesRequest](#sri_proto.RectifyNodeResolverMapEntriesRequest)
  
    * [RectifyNodeResolverMapEntriesResponse](#sri_proto.RectifyNodeResolverMapEntriesResponse)
  
    * [RegisteredEntry](#sri_proto.RegisteredEntry)
  
    * [Selector](#sri_proto.Selector)
  
    * [UpdateAttestedNodeEntryRequest](#sri_proto.UpdateAttestedNodeEntryRequest)
  
    * [UpdateAttestedNodeEntryResponse](#sri_proto.UpdateAttestedNodeEntryResponse)
  
    * [UpdateFederatedEntryRequest](#sri_proto.UpdateFederatedEntryRequest)
  
    * [UpdateFederatedEntryResponse](#sri_proto.UpdateFederatedEntryResponse)
  
    * [UpdateRegistrationEntryRequest](#sri_proto.UpdateRegistrationEntryRequest)
  
    * [UpdateRegistrationEntryResponse](#sri_proto.UpdateRegistrationEntryResponse)
  
  
  
  
    * [DataStore](#sri_proto.DataStore)
  

* [Scalar Value Types](#scalar-value-types)



<a name="common.proto"/>
<p align="right"><a href="#top">Top</a></p>

## common.proto



<a name="sri_proto.ConfigureRequest"/>

### ConfigureRequest
Represents the plugin-specific configuration string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| configuration | [string](#string) |  | The configuration for the plugin. |






<a name="sri_proto.ConfigureResponse"/>

### ConfigureResponse
Represents a list of configuration problems found in the configuration string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| errorList | [string](#string) | repeated | A list of errors. |






<a name="sri_proto.GetPluginInfoRequest"/>

### GetPluginInfoRequest
Represents an empty request.






<a name="sri_proto.GetPluginInfoResponse"/>

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



<a name="sri_proto.AttestedNodeEntry"/>

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






<a name="sri_proto.CreateAttestedNodeEntryRequest"/>

### CreateAttestedNodeEntryRequest
Represents an Attested Node entry to create


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#sri_proto.AttestedNodeEntry) |  | Attested node entry |






<a name="sri_proto.CreateAttestedNodeEntryResponse"/>

### CreateAttestedNodeEntryResponse
Represents the created Attested Node entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#sri_proto.AttestedNodeEntry) |  | Attested node entry |






<a name="sri_proto.CreateFederatedEntryRequest"/>

### CreateFederatedEntryRequest
Represents a Federated bundle


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#sri_proto.FederatedBundle) |  | Federated bundle |






<a name="sri_proto.CreateFederatedEntryResponse"/>

### CreateFederatedEntryResponse
Empty






<a name="sri_proto.CreateNodeResolverMapEntryRequest"/>

### CreateNodeResolverMapEntryRequest
Represents a Node resolver map entry to create


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntry | [NodeResolverMapEntry](#sri_proto.NodeResolverMapEntry) |  | Node resolver map entry |






<a name="sri_proto.CreateNodeResolverMapEntryResponse"/>

### CreateNodeResolverMapEntryResponse
Represents the created Node resolver map entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntry | [NodeResolverMapEntry](#sri_proto.NodeResolverMapEntry) |  | Node resolver map entry |






<a name="sri_proto.CreateRegistrationEntryRequest"/>

### CreateRegistrationEntryRequest
Represents a Registration entry to create


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [RegisteredEntry](#sri_proto.RegisteredEntry) |  | Registration entry |






<a name="sri_proto.CreateRegistrationEntryResponse"/>

### CreateRegistrationEntryResponse
Represents the created Registration entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryId | [string](#string) |  | Registration entry ID |






<a name="sri_proto.DeleteAttestedNodeEntryRequest"/>

### DeleteAttestedNodeEntryRequest
Represents the Spiffe ID of the Attested node entry to delete


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | SPIFFE ID |






<a name="sri_proto.DeleteAttestedNodeEntryResponse"/>

### DeleteAttestedNodeEntryResponse
Represents the deleted Attested node entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#sri_proto.AttestedNodeEntry) |  |  |






<a name="sri_proto.DeleteFederatedEntryRequest"/>

### DeleteFederatedEntryRequest
Represents the Spiffe ID of the federated bundle to delete


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundleSpiffeId | [string](#string) |  | SPIFFE ID of foreign trust domain |






<a name="sri_proto.DeleteFederatedEntryResponse"/>

### DeleteFederatedEntryResponse
Represents the deleted federated bundle


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#sri_proto.FederatedBundle) |  | Federated bundle |






<a name="sri_proto.DeleteNodeResolverMapEntryRequest"/>

### DeleteNodeResolverMapEntryRequest
Represents a Node resolver map entry to delete


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntry | [NodeResolverMapEntry](#sri_proto.NodeResolverMapEntry) |  | Node resolver map entry |






<a name="sri_proto.DeleteNodeResolverMapEntryResponse"/>

### DeleteNodeResolverMapEntryResponse
Represents a list of Node resolver map entries


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntryList | [NodeResolverMapEntry](#sri_proto.NodeResolverMapEntry) | repeated | List of Node resolver map entries |






<a name="sri_proto.DeleteRegistrationEntryRequest"/>

### DeleteRegistrationEntryRequest
Represents a Registration entry ID to delete


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryId | [string](#string) |  | Registration entry ID |






<a name="sri_proto.DeleteRegistrationEntryResponse"/>

### DeleteRegistrationEntryResponse
Represents the deleted Registration entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [RegisteredEntry](#sri_proto.RegisteredEntry) |  | Registration entry |






<a name="sri_proto.FederatedBundle"/>

### FederatedBundle
Represents the trust chain for a different trust domain, along with
a TTL describing its expiration, keyed by the SPIFFE ID of the foreign
trust domain.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundleSpiffeId | [string](#string) |  | Foreign trust domain SPIFFE ID |
| federatedTrustBundle | [bytes](#bytes) |  | Trust chain |
| ttl | [int32](#int32) |  | TTL |






<a name="sri_proto.FetchAttestedNodeEntryRequest"/>

### FetchAttestedNodeEntryRequest
Represents the Spiffe ID of the node entry to retrieve


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | SPIFFE ID |






<a name="sri_proto.FetchAttestedNodeEntryResponse"/>

### FetchAttestedNodeEntryResponse
Represents an Attested Node entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#sri_proto.AttestedNodeEntry) |  | Attested node entry |






<a name="sri_proto.FetchNodeResolverMapEntryRequest"/>

### FetchNodeResolverMapEntryRequest
Represents a Spiffe ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | SPIFFE ID |






<a name="sri_proto.FetchNodeResolverMapEntryResponse"/>

### FetchNodeResolverMapEntryResponse
Represents a list of Node resolver map entries for the specified Spiffe ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntryList | [NodeResolverMapEntry](#sri_proto.NodeResolverMapEntry) | repeated | List of Node resolver map entries |






<a name="sri_proto.FetchRegistrationEntryRequest"/>

### FetchRegistrationEntryRequest
Represents a Registration entry ID to fetch


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryId | [string](#string) |  | Registration entry ID |






<a name="sri_proto.FetchRegistrationEntryResponse"/>

### FetchRegistrationEntryResponse
Represents a Registration entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [RegisteredEntry](#sri_proto.RegisteredEntry) |  | Registration entry |






<a name="sri_proto.FetchStaleNodeEntriesRequest"/>

### FetchStaleNodeEntriesRequest
Empty






<a name="sri_proto.FetchStaleNodeEntriesResponse"/>

### FetchStaleNodeEntriesResponse
Represents dead nodes for which the base SVID has expired


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntryList | [AttestedNodeEntry](#sri_proto.AttestedNodeEntry) | repeated | List of attested node entries |






<a name="sri_proto.ListFederatedEntryRequest"/>

### ListFederatedEntryRequest
Empty






<a name="sri_proto.ListFederatedEntryResponse"/>

### ListFederatedEntryResponse
Represents a list of SPIFFE IDs of foreign trust domains


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundleSpiffeIdList | [string](#string) | repeated | SPIFFE IDs of foreign trust domains |






<a name="sri_proto.ListParentIDEntriesRequest"/>

### ListParentIDEntriesRequest
Represents a Parent ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| parentId | [string](#string) |  | Parent ID |






<a name="sri_proto.ListParentIDEntriesResponse"/>

### ListParentIDEntriesResponse
Represents a list of Registered entries with the specified Parent ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryList | [RegisteredEntry](#sri_proto.RegisteredEntry) | repeated | List of Registration entries |






<a name="sri_proto.ListSelectorEntriesRequest"/>

### ListSelectorEntriesRequest
Represents a selector


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selector | [Selector](#sri_proto.Selector) |  | Selector |






<a name="sri_proto.ListSelectorEntriesResponse"/>

### ListSelectorEntriesResponse
Represents a list of Registered entries with the specified selector


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryList | [RegisteredEntry](#sri_proto.RegisteredEntry) | repeated | List of Registration entries |






<a name="sri_proto.ListSpiffeEntriesRequest"/>

### ListSpiffeEntriesRequest
Represents a Spiffe ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeId | [string](#string) |  | Spiffe ID |






<a name="sri_proto.ListSpiffeEntriesResponse"/>

### ListSpiffeEntriesResponse
Represents a list of Registered entries with the specified Spiffe ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryList | [RegisteredEntry](#sri_proto.RegisteredEntry) | repeated | List of Registration entries |






<a name="sri_proto.NodeResolverMapEntry"/>

### NodeResolverMapEntry
Represents a single entry in NodeResolverMap and maps node properties to
logical attributes (i.e. an AWS instance to its ASG).


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  |  |
| selector | [Selector](#sri_proto.Selector) |  |  |






<a name="sri_proto.RectifyNodeResolverMapEntriesRequest"/>

### RectifyNodeResolverMapEntriesRequest
Represents a list of Node resolver map entries


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntryList | [NodeResolverMapEntry](#sri_proto.NodeResolverMapEntry) | repeated | List of Node resolver map entries |






<a name="sri_proto.RectifyNodeResolverMapEntriesResponse"/>

### RectifyNodeResolverMapEntriesResponse
Represents a list of Node resolver map entries


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntryList | [NodeResolverMapEntry](#sri_proto.NodeResolverMapEntry) | repeated | List of Node resolver map entries |






<a name="sri_proto.RegisteredEntry"/>

### RegisteredEntry
Represents a single Registration Entry.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectorList | [Selector](#sri_proto.Selector) | repeated | Array of selectors |
| spiffeId | [string](#string) |  | SPIFFE ID |
| parentId | [string](#string) |  | Attestor SPIFFE ID |
| ttl | [int32](#int32) |  | TTL |
| federatedBundleSpiffeIdList | [string](#string) | repeated | SPIFFE IDs of foreign trust domains |






<a name="sri_proto.Selector"/>

### Selector
Describes the conditions under which a registration entry is matched.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [string](#string) |  | Selector type |
| value | [string](#string) |  | Selector value |






<a name="sri_proto.UpdateAttestedNodeEntryRequest"/>

### UpdateAttestedNodeEntryRequest
Represents Attested node entry fields to update


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | Spiffe ID |
| certSerialNumber | [string](#string) |  | Serial number |
| certExpirationDate | [string](#string) |  | Expiration date |






<a name="sri_proto.UpdateAttestedNodeEntryResponse"/>

### UpdateAttestedNodeEntryResponse
Represents the updated Attested node entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#sri_proto.AttestedNodeEntry) |  | Attested node entry |






<a name="sri_proto.UpdateFederatedEntryRequest"/>

### UpdateFederatedEntryRequest
Represents a federated bundle to update


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#sri_proto.FederatedBundle) |  | Federated bundle |






<a name="sri_proto.UpdateFederatedEntryResponse"/>

### UpdateFederatedEntryResponse
Represents the updated federated bundle


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#sri_proto.FederatedBundle) |  | Federated bundle |






<a name="sri_proto.UpdateRegistrationEntryRequest"/>

### UpdateRegistrationEntryRequest
Represents a Registration entry to update


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryId | [string](#string) |  | Registration entry ID |
| registeredEntry | [RegisteredEntry](#sri_proto.RegisteredEntry) |  | Registration entry |






<a name="sri_proto.UpdateRegistrationEntryResponse"/>

### UpdateRegistrationEntryResponse
Represents the updated Registration entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [RegisteredEntry](#sri_proto.RegisteredEntry) |  | Registration entry |





 

 

 


<a name="sri_proto.DataStore"/>

### DataStore


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| CreateFederatedEntry | [CreateFederatedEntryRequest](#sri_proto.CreateFederatedEntryRequest) | [CreateFederatedEntryResponse](#sri_proto.CreateFederatedEntryRequest) | Creates a Federated Bundle |
| ListFederatedEntry | [ListFederatedEntryRequest](#sri_proto.ListFederatedEntryRequest) | [ListFederatedEntryResponse](#sri_proto.ListFederatedEntryRequest) | List all Federated SPIFFE IDs |
| UpdateFederatedEntry | [UpdateFederatedEntryRequest](#sri_proto.UpdateFederatedEntryRequest) | [UpdateFederatedEntryResponse](#sri_proto.UpdateFederatedEntryRequest) | Updates the specified Federated Bundle |
| DeleteFederatedEntry | [DeleteFederatedEntryRequest](#sri_proto.DeleteFederatedEntryRequest) | [DeleteFederatedEntryResponse](#sri_proto.DeleteFederatedEntryRequest) | Deletes the specified Federated Bundle |
| CreateAttestedNodeEntry | [CreateAttestedNodeEntryRequest](#sri_proto.CreateAttestedNodeEntryRequest) | [CreateAttestedNodeEntryResponse](#sri_proto.CreateAttestedNodeEntryRequest) | Creates an Attested Node Entry |
| FetchAttestedNodeEntry | [FetchAttestedNodeEntryRequest](#sri_proto.FetchAttestedNodeEntryRequest) | [FetchAttestedNodeEntryResponse](#sri_proto.FetchAttestedNodeEntryRequest) | Retrieves the Attested Node Entry |
| FetchStaleNodeEntries | [FetchStaleNodeEntriesRequest](#sri_proto.FetchStaleNodeEntriesRequest) | [FetchStaleNodeEntriesResponse](#sri_proto.FetchStaleNodeEntriesRequest) | Retrieves dead nodes for which the base SVID has expired |
| UpdateAttestedNodeEntry | [UpdateAttestedNodeEntryRequest](#sri_proto.UpdateAttestedNodeEntryRequest) | [UpdateAttestedNodeEntryResponse](#sri_proto.UpdateAttestedNodeEntryRequest) | Updates the Attested Node Entry |
| DeleteAttestedNodeEntry | [DeleteAttestedNodeEntryRequest](#sri_proto.DeleteAttestedNodeEntryRequest) | [DeleteAttestedNodeEntryResponse](#sri_proto.DeleteAttestedNodeEntryRequest) | Deletes the Attested Node Entry |
| CreateNodeResolverMapEntry | [CreateNodeResolverMapEntryRequest](#sri_proto.CreateNodeResolverMapEntryRequest) | [CreateNodeResolverMapEntryResponse](#sri_proto.CreateNodeResolverMapEntryRequest) | Creates a Node resolver map Entry |
| FetchNodeResolverMapEntry | [FetchNodeResolverMapEntryRequest](#sri_proto.FetchNodeResolverMapEntryRequest) | [FetchNodeResolverMapEntryResponse](#sri_proto.FetchNodeResolverMapEntryRequest) | Retrieves all Node Resolver Map Entry for the specific base SPIFFEID |
| DeleteNodeResolverMapEntry | [DeleteNodeResolverMapEntryRequest](#sri_proto.DeleteNodeResolverMapEntryRequest) | [DeleteNodeResolverMapEntryResponse](#sri_proto.DeleteNodeResolverMapEntryRequest) | Deletes all Node Resolver Map Entry for the specific base SPIFFEID |
| RectifyNodeResolverMapEntries | [RectifyNodeResolverMapEntriesRequest](#sri_proto.RectifyNodeResolverMapEntriesRequest) | [RectifyNodeResolverMapEntriesResponse](#sri_proto.RectifyNodeResolverMapEntriesRequest) | Used for rectifying updated node resolutions |
| CreateRegistrationEntry | [CreateRegistrationEntryRequest](#sri_proto.CreateRegistrationEntryRequest) | [CreateRegistrationEntryResponse](#sri_proto.CreateRegistrationEntryRequest) | Creates a Registered Entry |
| FetchRegistrationEntry | [FetchRegistrationEntryRequest](#sri_proto.FetchRegistrationEntryRequest) | [FetchRegistrationEntryResponse](#sri_proto.FetchRegistrationEntryRequest) | Retrieve a specific registered entry |
| UpdateRegistrationEntry | [UpdateRegistrationEntryRequest](#sri_proto.UpdateRegistrationEntryRequest) | [UpdateRegistrationEntryResponse](#sri_proto.UpdateRegistrationEntryRequest) | Updates a specific registered entry |
| DeleteRegistrationEntry | [DeleteRegistrationEntryRequest](#sri_proto.DeleteRegistrationEntryRequest) | [DeleteRegistrationEntryResponse](#sri_proto.DeleteRegistrationEntryRequest) | Deletes a specific registered entry |
| ListParentIDEntries | [ListParentIDEntriesRequest](#sri_proto.ListParentIDEntriesRequest) | [ListParentIDEntriesResponse](#sri_proto.ListParentIDEntriesRequest) | Retrieves all the  registered entry with the same ParentID |
| ListSelectorEntries | [ListSelectorEntriesRequest](#sri_proto.ListSelectorEntriesRequest) | [ListSelectorEntriesResponse](#sri_proto.ListSelectorEntriesRequest) | Retrieves all the  registered entry with the same Selector |
| ListSpiffeEntries | [ListSpiffeEntriesRequest](#sri_proto.ListSpiffeEntriesRequest) | [ListSpiffeEntriesResponse](#sri_proto.ListSpiffeEntriesRequest) | Retrieves all the  registered entry with the same SpiffeId |
| Configure | [ConfigureRequest](#sri_proto.ConfigureRequest) | [ConfigureResponse](#sri_proto.ConfigureRequest) | Applies the plugin configuration |
| GetPluginInfo | [GetPluginInfoRequest](#sri_proto.GetPluginInfoRequest) | [GetPluginInfoResponse](#sri_proto.GetPluginInfoRequest) | Returns the version and related metadata of the installed plugin |

 



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

