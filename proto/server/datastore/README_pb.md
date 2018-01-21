# Protocol Documentation
<a name="top"/>

## Table of Contents

- [plugin.proto](#plugin.proto)
    - [ConfigureRequest](#spire.common.plugin.ConfigureRequest)
    - [ConfigureResponse](#spire.common.plugin.ConfigureResponse)
    - [GetPluginInfoRequest](#spire.common.plugin.GetPluginInfoRequest)
    - [GetPluginInfoResponse](#spire.common.plugin.GetPluginInfoResponse)
    - [PluginInfoReply](#spire.common.plugin.PluginInfoReply)
    - [PluginInfoRequest](#spire.common.plugin.PluginInfoRequest)
    - [StopReply](#spire.common.plugin.StopReply)
    - [StopRequest](#spire.common.plugin.StopRequest)
  
  
  
    - [Server](#spire.common.plugin.Server)
  

- [common.proto](#common.proto)
    - [AttestedData](#spire.common.AttestedData)
    - [Empty](#spire.common.Empty)
    - [RegistrationEntries](#spire.common.RegistrationEntries)
    - [RegistrationEntry](#spire.common.RegistrationEntry)
    - [Selector](#spire.common.Selector)
    - [Selectors](#spire.common.Selectors)
  
  
  
  

- [datastore.proto](#datastore.proto)
    - [AttestedNodeEntry](#spire.server.datastore.AttestedNodeEntry)
    - [CreateAttestedNodeEntryRequest](#spire.server.datastore.CreateAttestedNodeEntryRequest)
    - [CreateAttestedNodeEntryResponse](#spire.server.datastore.CreateAttestedNodeEntryResponse)
    - [CreateFederatedEntryRequest](#spire.server.datastore.CreateFederatedEntryRequest)
    - [CreateFederatedEntryResponse](#spire.server.datastore.CreateFederatedEntryResponse)
    - [CreateNodeResolverMapEntryRequest](#spire.server.datastore.CreateNodeResolverMapEntryRequest)
    - [CreateNodeResolverMapEntryResponse](#spire.server.datastore.CreateNodeResolverMapEntryResponse)
    - [CreateRegistrationEntryRequest](#spire.server.datastore.CreateRegistrationEntryRequest)
    - [CreateRegistrationEntryResponse](#spire.server.datastore.CreateRegistrationEntryResponse)
    - [DeleteAttestedNodeEntryRequest](#spire.server.datastore.DeleteAttestedNodeEntryRequest)
    - [DeleteAttestedNodeEntryResponse](#spire.server.datastore.DeleteAttestedNodeEntryResponse)
    - [DeleteFederatedEntryRequest](#spire.server.datastore.DeleteFederatedEntryRequest)
    - [DeleteFederatedEntryResponse](#spire.server.datastore.DeleteFederatedEntryResponse)
    - [DeleteNodeResolverMapEntryRequest](#spire.server.datastore.DeleteNodeResolverMapEntryRequest)
    - [DeleteNodeResolverMapEntryResponse](#spire.server.datastore.DeleteNodeResolverMapEntryResponse)
    - [DeleteRegistrationEntryRequest](#spire.server.datastore.DeleteRegistrationEntryRequest)
    - [DeleteRegistrationEntryResponse](#spire.server.datastore.DeleteRegistrationEntryResponse)
    - [FederatedBundle](#spire.server.datastore.FederatedBundle)
    - [FetchAttestedNodeEntryRequest](#spire.server.datastore.FetchAttestedNodeEntryRequest)
    - [FetchAttestedNodeEntryResponse](#spire.server.datastore.FetchAttestedNodeEntryResponse)
    - [FetchNodeResolverMapEntryRequest](#spire.server.datastore.FetchNodeResolverMapEntryRequest)
    - [FetchNodeResolverMapEntryResponse](#spire.server.datastore.FetchNodeResolverMapEntryResponse)
    - [FetchRegistrationEntriesResponse](#spire.server.datastore.FetchRegistrationEntriesResponse)
    - [FetchRegistrationEntryRequest](#spire.server.datastore.FetchRegistrationEntryRequest)
    - [FetchRegistrationEntryResponse](#spire.server.datastore.FetchRegistrationEntryResponse)
    - [FetchStaleNodeEntriesRequest](#spire.server.datastore.FetchStaleNodeEntriesRequest)
    - [FetchStaleNodeEntriesResponse](#spire.server.datastore.FetchStaleNodeEntriesResponse)
    - [JoinToken](#spire.server.datastore.JoinToken)
    - [ListFederatedEntryRequest](#spire.server.datastore.ListFederatedEntryRequest)
    - [ListFederatedEntryResponse](#spire.server.datastore.ListFederatedEntryResponse)
    - [ListParentIDEntriesRequest](#spire.server.datastore.ListParentIDEntriesRequest)
    - [ListParentIDEntriesResponse](#spire.server.datastore.ListParentIDEntriesResponse)
    - [ListSelectorEntriesRequest](#spire.server.datastore.ListSelectorEntriesRequest)
    - [ListSelectorEntriesResponse](#spire.server.datastore.ListSelectorEntriesResponse)
    - [ListSpiffeEntriesRequest](#spire.server.datastore.ListSpiffeEntriesRequest)
    - [ListSpiffeEntriesResponse](#spire.server.datastore.ListSpiffeEntriesResponse)
    - [NodeResolverMapEntry](#spire.server.datastore.NodeResolverMapEntry)
    - [RectifyNodeResolverMapEntriesRequest](#spire.server.datastore.RectifyNodeResolverMapEntriesRequest)
    - [RectifyNodeResolverMapEntriesResponse](#spire.server.datastore.RectifyNodeResolverMapEntriesResponse)
    - [UpdateAttestedNodeEntryRequest](#spire.server.datastore.UpdateAttestedNodeEntryRequest)
    - [UpdateAttestedNodeEntryResponse](#spire.server.datastore.UpdateAttestedNodeEntryResponse)
    - [UpdateFederatedEntryRequest](#spire.server.datastore.UpdateFederatedEntryRequest)
    - [UpdateFederatedEntryResponse](#spire.server.datastore.UpdateFederatedEntryResponse)
    - [UpdateRegistrationEntryRequest](#spire.server.datastore.UpdateRegistrationEntryRequest)
    - [UpdateRegistrationEntryResponse](#spire.server.datastore.UpdateRegistrationEntryResponse)
  
  
  
    - [DataStore](#spire.server.datastore.DataStore)
  

- [Scalar Value Types](#scalar-value-types)



<a name="plugin.proto"/>
<p align="right"><a href="#top">Top</a></p>

## plugin.proto



<a name="spire.common.plugin.ConfigureRequest"/>

### ConfigureRequest
Represents the plugin-specific configuration string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| configuration | [string](#string) |  | The configuration for the plugin. |






<a name="spire.common.plugin.ConfigureResponse"/>

### ConfigureResponse
Represents a list of configuration problems
found in the configuration string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| errorList | [string](#string) | repeated | A list of errors |






<a name="spire.common.plugin.GetPluginInfoRequest"/>

### GetPluginInfoRequest
Represents an empty request.






<a name="spire.common.plugin.GetPluginInfoResponse"/>

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






<a name="spire.common.plugin.PluginInfoReply"/>

### PluginInfoReply



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| pluginInfo | [GetPluginInfoResponse](#spire.common.plugin.GetPluginInfoResponse) | repeated |  |






<a name="spire.common.plugin.PluginInfoRequest"/>

### PluginInfoRequest







<a name="spire.common.plugin.StopReply"/>

### StopReply







<a name="spire.common.plugin.StopRequest"/>

### StopRequest






 

 

 


<a name="spire.common.plugin.Server"/>

### Server


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Stop | [StopRequest](#spire.common.plugin.StopRequest) | [StopReply](#spire.common.plugin.StopRequest) |  |
| PluginInfo | [PluginInfoRequest](#spire.common.plugin.PluginInfoRequest) | [PluginInfoReply](#spire.common.plugin.PluginInfoRequest) |  |

 



<a name="common.proto"/>
<p align="right"><a href="#top">Top</a></p>

## common.proto



<a name="spire.common.AttestedData"/>

### AttestedData
A type which contains attestation data for specific platform.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [string](#string) |  | Type of attestation to perform. |
| data | [bytes](#bytes) |  | The attestetion data. |






<a name="spire.common.Empty"/>

### Empty
Represents an empty message






<a name="spire.common.RegistrationEntries"/>

### RegistrationEntries
A list of registration entries.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entries | [RegistrationEntry](#spire.common.RegistrationEntry) | repeated | A list of RegistrationEntry. |






<a name="spire.common.RegistrationEntry"/>

### RegistrationEntry
This is a curated record that the Control Plane uses to set up and
manage the various registered nodes and workloads that are controlled by it.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectors | [Selector](#spire.common.Selector) | repeated | A list of selectors. |
| parent_id | [string](#string) |  | The SPIFFE ID of an entity that is authorized to attest the validity of a selector |
| spiffe_id | [string](#string) |  | The SPIFFE ID is a structured string used to identify a resource or caller. It is defined as a URI comprising a “trust domain” and an associated path. |
| ttl | [int32](#int32) |  | Time to live. |
| fb_spiffe_ids | [string](#string) | repeated | A list of federated bundle spiffe ids. |






<a name="spire.common.Selector"/>

### Selector
A type which describes the conditions under which a registration
entry is matched.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [string](#string) |  | A selector type represents the type of attestation used in attesting the entity (Eg: AWS, K8). |
| value | [string](#string) |  | The value to be attested. |






<a name="spire.common.Selectors"/>

### Selectors
Represents a type with a list of NodeResolution.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entries | [Selector](#spire.common.Selector) | repeated | A list of NodeResolution. |





 

 

 

 



<a name="datastore.proto"/>
<p align="right"><a href="#top">Top</a></p>

## datastore.proto



<a name="spire.server.datastore.AttestedNodeEntry"/>

### AttestedNodeEntry
Represents a single entry in AttestedNodes and stores the node&#39;s
SPIFFE ID, the type of attestation it performed, as well as the serial
number and expiration date of its node SVID.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | Spiffe ID |
| attestedDataType | [string](#string) |  | Attestation type |
| certSerialNumber | [string](#string) |  | Serial number |
| certExpirationDate | [string](#string) |  | Expiration date |






<a name="spire.server.datastore.CreateAttestedNodeEntryRequest"/>

### CreateAttestedNodeEntryRequest
Represents an Attested Node entry to create


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#spire.server.datastore.AttestedNodeEntry) |  | Attested node entry |






<a name="spire.server.datastore.CreateAttestedNodeEntryResponse"/>

### CreateAttestedNodeEntryResponse
Represents the created Attested Node entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#spire.server.datastore.AttestedNodeEntry) |  | Attested node entry |






<a name="spire.server.datastore.CreateFederatedEntryRequest"/>

### CreateFederatedEntryRequest
Represents a Federated bundle


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#spire.server.datastore.FederatedBundle) |  | Federated bundle |






<a name="spire.server.datastore.CreateFederatedEntryResponse"/>

### CreateFederatedEntryResponse
Empty response






<a name="spire.server.datastore.CreateNodeResolverMapEntryRequest"/>

### CreateNodeResolverMapEntryRequest
Represents a Node resolver map entry to create


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntry | [NodeResolverMapEntry](#spire.server.datastore.NodeResolverMapEntry) |  | Node resolver map entry |






<a name="spire.server.datastore.CreateNodeResolverMapEntryResponse"/>

### CreateNodeResolverMapEntryResponse
Represents the created Node resolver map entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntry | [NodeResolverMapEntry](#spire.server.datastore.NodeResolverMapEntry) |  | Node resolver map entry |






<a name="spire.server.datastore.CreateRegistrationEntryRequest"/>

### CreateRegistrationEntryRequest
Represents a Registration entry to create


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [.spire.common.RegistrationEntry](#spire.server.datastore..spire.common.RegistrationEntry) |  | Registration entry |






<a name="spire.server.datastore.CreateRegistrationEntryResponse"/>

### CreateRegistrationEntryResponse
Represents the created Registration entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryId | [string](#string) |  | Registration entry ID |






<a name="spire.server.datastore.DeleteAttestedNodeEntryRequest"/>

### DeleteAttestedNodeEntryRequest
Represents the Spiffe ID of the Attested node entry to delete


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | SPIFFE ID |






<a name="spire.server.datastore.DeleteAttestedNodeEntryResponse"/>

### DeleteAttestedNodeEntryResponse
Represents the deleted Attested node entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#spire.server.datastore.AttestedNodeEntry) |  |  |






<a name="spire.server.datastore.DeleteFederatedEntryRequest"/>

### DeleteFederatedEntryRequest
Represents the Spiffe ID of the federated bundle to delete


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundleSpiffeId | [string](#string) |  | SPIFFE ID of foreign trust domain |






<a name="spire.server.datastore.DeleteFederatedEntryResponse"/>

### DeleteFederatedEntryResponse
Represents the deleted federated bundle


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#spire.server.datastore.FederatedBundle) |  | Federated bundle |






<a name="spire.server.datastore.DeleteNodeResolverMapEntryRequest"/>

### DeleteNodeResolverMapEntryRequest
Represents a Node resolver map entry to delete


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntry | [NodeResolverMapEntry](#spire.server.datastore.NodeResolverMapEntry) |  | Node resolver map entry |






<a name="spire.server.datastore.DeleteNodeResolverMapEntryResponse"/>

### DeleteNodeResolverMapEntryResponse
Represents a list of Node resolver map entries


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntryList | [NodeResolverMapEntry](#spire.server.datastore.NodeResolverMapEntry) | repeated | List of Node resolver map entries |






<a name="spire.server.datastore.DeleteRegistrationEntryRequest"/>

### DeleteRegistrationEntryRequest
Represents a Registration entry ID to delete


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryId | [string](#string) |  | Registration entry ID |






<a name="spire.server.datastore.DeleteRegistrationEntryResponse"/>

### DeleteRegistrationEntryResponse
Represents the deleted Registration entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [.spire.common.RegistrationEntry](#spire.server.datastore..spire.common.RegistrationEntry) |  | Registration entry |






<a name="spire.server.datastore.FederatedBundle"/>

### FederatedBundle
Represents the trust chain for a different trust domain, along with
a TTL describing its expiration, keyed by the SPIFFE ID of the foreign
trust domain.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundleSpiffeId | [string](#string) |  | Foreign trust domain SPIFFE ID |
| federatedTrustBundle | [bytes](#bytes) |  | Trust chain |
| ttl | [int32](#int32) |  | TTL |






<a name="spire.server.datastore.FetchAttestedNodeEntryRequest"/>

### FetchAttestedNodeEntryRequest
Represents the Spiffe ID of the node entry to retrieve


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | SPIFFE ID |






<a name="spire.server.datastore.FetchAttestedNodeEntryResponse"/>

### FetchAttestedNodeEntryResponse
Represents an Attested Node entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#spire.server.datastore.AttestedNodeEntry) |  | Attested node entry |






<a name="spire.server.datastore.FetchNodeResolverMapEntryRequest"/>

### FetchNodeResolverMapEntryRequest
Represents a Spiffe ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | SPIFFE ID |






<a name="spire.server.datastore.FetchNodeResolverMapEntryResponse"/>

### FetchNodeResolverMapEntryResponse
Represents a list of Node resolver map entries for the specified Spiffe ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntryList | [NodeResolverMapEntry](#spire.server.datastore.NodeResolverMapEntry) | repeated | List of Node resolver map entries |






<a name="spire.server.datastore.FetchRegistrationEntriesResponse"/>

### FetchRegistrationEntriesResponse
Represents a list of Registration entries


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntries | [.spire.common.RegistrationEntries](#spire.server.datastore..spire.common.RegistrationEntries) |  | Registration entries |






<a name="spire.server.datastore.FetchRegistrationEntryRequest"/>

### FetchRegistrationEntryRequest
Represents a Registration entry ID to fetch


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryId | [string](#string) |  | Registration entry ID |






<a name="spire.server.datastore.FetchRegistrationEntryResponse"/>

### FetchRegistrationEntryResponse
Represents a Registration entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [.spire.common.RegistrationEntry](#spire.server.datastore..spire.common.RegistrationEntry) |  | Registration entry |






<a name="spire.server.datastore.FetchStaleNodeEntriesRequest"/>

### FetchStaleNodeEntriesRequest
Empty Request






<a name="spire.server.datastore.FetchStaleNodeEntriesResponse"/>

### FetchStaleNodeEntriesResponse
Represents dead nodes for which the base SVID has expired


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntryList | [AttestedNodeEntry](#spire.server.datastore.AttestedNodeEntry) | repeated | List of attested node entries |






<a name="spire.server.datastore.JoinToken"/>

### JoinToken
Represents a join token and associated metadata, if known


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| token | [string](#string) |  |  |
| expiry | [int64](#int64) |  | Expiration date, represented in UNIX time |






<a name="spire.server.datastore.ListFederatedEntryRequest"/>

### ListFederatedEntryRequest
Empty Request






<a name="spire.server.datastore.ListFederatedEntryResponse"/>

### ListFederatedEntryResponse
Represents a list of SPIFFE IDs of foreign trust domains


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundleSpiffeIdList | [string](#string) | repeated | SPIFFE IDs of foreign trust domains |






<a name="spire.server.datastore.ListParentIDEntriesRequest"/>

### ListParentIDEntriesRequest
Represents a Parent ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| parentId | [string](#string) |  | Parent ID |






<a name="spire.server.datastore.ListParentIDEntriesResponse"/>

### ListParentIDEntriesResponse
Represents a list of Registered entries with the specified Parent ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryList | [.spire.common.RegistrationEntry](#spire.server.datastore..spire.common.RegistrationEntry) | repeated | List of Registration entries |






<a name="spire.server.datastore.ListSelectorEntriesRequest"/>

### ListSelectorEntriesRequest
Represents a selector


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectors | [.spire.common.Selector](#spire.server.datastore..spire.common.Selector) | repeated | Selector |






<a name="spire.server.datastore.ListSelectorEntriesResponse"/>

### ListSelectorEntriesResponse
Represents a list of Registered entries with the specified selector


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryList | [.spire.common.RegistrationEntry](#spire.server.datastore..spire.common.RegistrationEntry) | repeated | List of Registration entries |






<a name="spire.server.datastore.ListSpiffeEntriesRequest"/>

### ListSpiffeEntriesRequest
Represents a Spiffe ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeId | [string](#string) |  | SPIFFE ID |






<a name="spire.server.datastore.ListSpiffeEntriesResponse"/>

### ListSpiffeEntriesResponse
Represents a list of Registered entries with the specified Spiffe ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryList | [.spire.common.RegistrationEntry](#spire.server.datastore..spire.common.RegistrationEntry) | repeated | List of Registration entries |






<a name="spire.server.datastore.NodeResolverMapEntry"/>

### NodeResolverMapEntry
Represents a single entry in NodeResolverMap and maps node properties
to logical attributes (i.e. an AWS instance to its ASG).


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  |  |
| selector | [.spire.common.Selector](#spire.server.datastore..spire.common.Selector) |  |  |






<a name="spire.server.datastore.RectifyNodeResolverMapEntriesRequest"/>

### RectifyNodeResolverMapEntriesRequest
Represents a list of Node resolver map entries


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntryList | [NodeResolverMapEntry](#spire.server.datastore.NodeResolverMapEntry) | repeated | List of Node resolver map entries |






<a name="spire.server.datastore.RectifyNodeResolverMapEntriesResponse"/>

### RectifyNodeResolverMapEntriesResponse
Represents a list of Node resolver map entries


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntryList | [NodeResolverMapEntry](#spire.server.datastore.NodeResolverMapEntry) | repeated | List of Node resolver map entries |






<a name="spire.server.datastore.UpdateAttestedNodeEntryRequest"/>

### UpdateAttestedNodeEntryRequest
Represents Attested node entry fields to update


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | SPIFFE ID |
| certSerialNumber | [string](#string) |  | Serial number |
| certExpirationDate | [string](#string) |  | Expiration date |






<a name="spire.server.datastore.UpdateAttestedNodeEntryResponse"/>

### UpdateAttestedNodeEntryResponse
Represents the updated Attested node entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#spire.server.datastore.AttestedNodeEntry) |  | Attested node entry |






<a name="spire.server.datastore.UpdateFederatedEntryRequest"/>

### UpdateFederatedEntryRequest
Represents a federated bundle to update


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#spire.server.datastore.FederatedBundle) |  | Federated bundle |






<a name="spire.server.datastore.UpdateFederatedEntryResponse"/>

### UpdateFederatedEntryResponse
Represents the updated federated bundle


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#spire.server.datastore.FederatedBundle) |  | Federated bundle |






<a name="spire.server.datastore.UpdateRegistrationEntryRequest"/>

### UpdateRegistrationEntryRequest
Represents a Registration entry to update


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryId | [string](#string) |  | Registration entry ID |
| registeredEntry | [.spire.common.RegistrationEntry](#spire.server.datastore..spire.common.RegistrationEntry) |  | Registration entry |






<a name="spire.server.datastore.UpdateRegistrationEntryResponse"/>

### UpdateRegistrationEntryResponse
Represents the updated Registration entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [.spire.common.RegistrationEntry](#spire.server.datastore..spire.common.RegistrationEntry) |  | Registration entry |





 

 

 


<a name="spire.server.datastore.DataStore"/>

### DataStore


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| CreateFederatedEntry | [CreateFederatedEntryRequest](#spire.server.datastore.CreateFederatedEntryRequest) | [CreateFederatedEntryResponse](#spire.server.datastore.CreateFederatedEntryRequest) | Creates a Federated Bundle |
| ListFederatedEntry | [ListFederatedEntryRequest](#spire.server.datastore.ListFederatedEntryRequest) | [ListFederatedEntryResponse](#spire.server.datastore.ListFederatedEntryRequest) | List all Federated SPIFFE IDs |
| UpdateFederatedEntry | [UpdateFederatedEntryRequest](#spire.server.datastore.UpdateFederatedEntryRequest) | [UpdateFederatedEntryResponse](#spire.server.datastore.UpdateFederatedEntryRequest) | Updates the specified Federated Bundle |
| DeleteFederatedEntry | [DeleteFederatedEntryRequest](#spire.server.datastore.DeleteFederatedEntryRequest) | [DeleteFederatedEntryResponse](#spire.server.datastore.DeleteFederatedEntryRequest) | Deletes the specified Federated Bundle |
| CreateAttestedNodeEntry | [CreateAttestedNodeEntryRequest](#spire.server.datastore.CreateAttestedNodeEntryRequest) | [CreateAttestedNodeEntryResponse](#spire.server.datastore.CreateAttestedNodeEntryRequest) | Creates an Attested Node Entry |
| FetchAttestedNodeEntry | [FetchAttestedNodeEntryRequest](#spire.server.datastore.FetchAttestedNodeEntryRequest) | [FetchAttestedNodeEntryResponse](#spire.server.datastore.FetchAttestedNodeEntryRequest) | Retrieves the Attested Node Entry |
| FetchStaleNodeEntries | [FetchStaleNodeEntriesRequest](#spire.server.datastore.FetchStaleNodeEntriesRequest) | [FetchStaleNodeEntriesResponse](#spire.server.datastore.FetchStaleNodeEntriesRequest) | Retrieves dead nodes for which the base SVID has expired |
| UpdateAttestedNodeEntry | [UpdateAttestedNodeEntryRequest](#spire.server.datastore.UpdateAttestedNodeEntryRequest) | [UpdateAttestedNodeEntryResponse](#spire.server.datastore.UpdateAttestedNodeEntryRequest) | Updates the Attested Node Entry |
| DeleteAttestedNodeEntry | [DeleteAttestedNodeEntryRequest](#spire.server.datastore.DeleteAttestedNodeEntryRequest) | [DeleteAttestedNodeEntryResponse](#spire.server.datastore.DeleteAttestedNodeEntryRequest) | Deletes the Attested Node Entry |
| CreateNodeResolverMapEntry | [CreateNodeResolverMapEntryRequest](#spire.server.datastore.CreateNodeResolverMapEntryRequest) | [CreateNodeResolverMapEntryResponse](#spire.server.datastore.CreateNodeResolverMapEntryRequest) | Creates a Node resolver map Entry |
| FetchNodeResolverMapEntry | [FetchNodeResolverMapEntryRequest](#spire.server.datastore.FetchNodeResolverMapEntryRequest) | [FetchNodeResolverMapEntryResponse](#spire.server.datastore.FetchNodeResolverMapEntryRequest) | Retrieves all Node Resolver Map Entry for the specific base SPIFFEID |
| DeleteNodeResolverMapEntry | [DeleteNodeResolverMapEntryRequest](#spire.server.datastore.DeleteNodeResolverMapEntryRequest) | [DeleteNodeResolverMapEntryResponse](#spire.server.datastore.DeleteNodeResolverMapEntryRequest) | Deletes all Node Resolver Map Entry for the specific base SPIFFEID |
| RectifyNodeResolverMapEntries | [RectifyNodeResolverMapEntriesRequest](#spire.server.datastore.RectifyNodeResolverMapEntriesRequest) | [RectifyNodeResolverMapEntriesResponse](#spire.server.datastore.RectifyNodeResolverMapEntriesRequest) | Used for rectifying updated node resolutions |
| CreateRegistrationEntry | [CreateRegistrationEntryRequest](#spire.server.datastore.CreateRegistrationEntryRequest) | [CreateRegistrationEntryResponse](#spire.server.datastore.CreateRegistrationEntryRequest) | Creates a Registered Entry |
| FetchRegistrationEntry | [FetchRegistrationEntryRequest](#spire.server.datastore.FetchRegistrationEntryRequest) | [FetchRegistrationEntryResponse](#spire.server.datastore.FetchRegistrationEntryRequest) | Retrieve a specific registered entry |
| FetchRegistrationEntries | [spire.common.Empty](#spire.common.Empty) | [FetchRegistrationEntriesResponse](#spire.common.Empty) | Retrieve all registration entries |
| UpdateRegistrationEntry | [UpdateRegistrationEntryRequest](#spire.server.datastore.UpdateRegistrationEntryRequest) | [UpdateRegistrationEntryResponse](#spire.server.datastore.UpdateRegistrationEntryRequest) | Updates a specific registered entry |
| DeleteRegistrationEntry | [DeleteRegistrationEntryRequest](#spire.server.datastore.DeleteRegistrationEntryRequest) | [DeleteRegistrationEntryResponse](#spire.server.datastore.DeleteRegistrationEntryRequest) | Deletes a specific registered entry |
| ListParentIDEntries | [ListParentIDEntriesRequest](#spire.server.datastore.ListParentIDEntriesRequest) | [ListParentIDEntriesResponse](#spire.server.datastore.ListParentIDEntriesRequest) | Retrieves all the registered entry with the same ParentID |
| ListSelectorEntries | [ListSelectorEntriesRequest](#spire.server.datastore.ListSelectorEntriesRequest) | [ListSelectorEntriesResponse](#spire.server.datastore.ListSelectorEntriesRequest) | Retrieves all the registered entry matching exactly the compound Selector |
| ListMatchingEntries | [ListSelectorEntriesRequest](#spire.server.datastore.ListSelectorEntriesRequest) | [ListSelectorEntriesResponse](#spire.server.datastore.ListSelectorEntriesRequest) | Retrieves registered entries containing all of the specified selectors |
| ListSpiffeEntries | [ListSpiffeEntriesRequest](#spire.server.datastore.ListSpiffeEntriesRequest) | [ListSpiffeEntriesResponse](#spire.server.datastore.ListSpiffeEntriesRequest) | Retrieves all the registered entry with the same SpiffeId |
| RegisterToken | [JoinToken](#spire.server.datastore.JoinToken) | [spire.common.Empty](#spire.server.datastore.JoinToken) | Register a new join token |
| FetchToken | [JoinToken](#spire.server.datastore.JoinToken) | [JoinToken](#spire.server.datastore.JoinToken) | Fetch a token record |
| DeleteToken | [JoinToken](#spire.server.datastore.JoinToken) | [spire.common.Empty](#spire.server.datastore.JoinToken) | Delete the referenced token |
| PruneTokens | [JoinToken](#spire.server.datastore.JoinToken) | [spire.common.Empty](#spire.server.datastore.JoinToken) | Delete all tokens with expiry less than the one specified |
| Configure | [spire.common.plugin.ConfigureRequest](#spire.common.plugin.ConfigureRequest) | [spire.common.plugin.ConfigureResponse](#spire.common.plugin.ConfigureRequest) | Applies the plugin configuration |
| GetPluginInfo | [spire.common.plugin.GetPluginInfoRequest](#spire.common.plugin.GetPluginInfoRequest) | [spire.common.plugin.GetPluginInfoResponse](#spire.common.plugin.GetPluginInfoRequest) | Returns the version and related metadata of the installed plugin |

 



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

