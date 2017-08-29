# Protocol Documentation
<a name="top"/>

## Table of Contents


* [plugin.proto](#plugin.proto)
  
    * [ConfigureRequest](#sriplugin.ConfigureRequest)
  
    * [ConfigureResponse](#sriplugin.ConfigureResponse)
  
    * [GetPluginInfoRequest](#sriplugin.GetPluginInfoRequest)
  
    * [GetPluginInfoResponse](#sriplugin.GetPluginInfoResponse)
  
    * [PluginInfoReply](#sriplugin.PluginInfoReply)
  
    * [PluginInfoRequest](#sriplugin.PluginInfoRequest)
  
    * [StopReply](#sriplugin.StopReply)
  
    * [StopRequest](#sriplugin.StopRequest)
  
  
  
  
    * [Server](#sriplugin.Server)
  


* [common.proto](#common.proto)
  
    * [AttestedData](#common.AttestedData)
  
    * [Empty](#common.Empty)
  
    * [RegistrationEntries](#common.RegistrationEntries)
  
    * [RegistrationEntry](#common.RegistrationEntry)
  
    * [Selector](#common.Selector)
  
    * [Selectors](#common.Selectors)
  
  
  
  


* [data_store.proto](#data_store.proto)
  
    * [AttestedNodeEntry](#datastore.AttestedNodeEntry)
  
    * [CreateAttestedNodeEntryRequest](#datastore.CreateAttestedNodeEntryRequest)
  
    * [CreateAttestedNodeEntryResponse](#datastore.CreateAttestedNodeEntryResponse)
  
    * [CreateFederatedEntryRequest](#datastore.CreateFederatedEntryRequest)
  
    * [CreateFederatedEntryResponse](#datastore.CreateFederatedEntryResponse)
  
    * [CreateNodeResolverMapEntryRequest](#datastore.CreateNodeResolverMapEntryRequest)
  
    * [CreateNodeResolverMapEntryResponse](#datastore.CreateNodeResolverMapEntryResponse)
  
    * [CreateRegistrationEntryRequest](#datastore.CreateRegistrationEntryRequest)
  
    * [CreateRegistrationEntryResponse](#datastore.CreateRegistrationEntryResponse)
  
    * [DeleteAttestedNodeEntryRequest](#datastore.DeleteAttestedNodeEntryRequest)
  
    * [DeleteAttestedNodeEntryResponse](#datastore.DeleteAttestedNodeEntryResponse)
  
    * [DeleteFederatedEntryRequest](#datastore.DeleteFederatedEntryRequest)
  
    * [DeleteFederatedEntryResponse](#datastore.DeleteFederatedEntryResponse)
  
    * [DeleteNodeResolverMapEntryRequest](#datastore.DeleteNodeResolverMapEntryRequest)
  
    * [DeleteNodeResolverMapEntryResponse](#datastore.DeleteNodeResolverMapEntryResponse)
  
    * [DeleteRegistrationEntryRequest](#datastore.DeleteRegistrationEntryRequest)
  
    * [DeleteRegistrationEntryResponse](#datastore.DeleteRegistrationEntryResponse)
  
    * [FederatedBundle](#datastore.FederatedBundle)
  
    * [FetchAttestedNodeEntryRequest](#datastore.FetchAttestedNodeEntryRequest)
  
    * [FetchAttestedNodeEntryResponse](#datastore.FetchAttestedNodeEntryResponse)
  
    * [FetchNodeResolverMapEntryRequest](#datastore.FetchNodeResolverMapEntryRequest)
  
    * [FetchNodeResolverMapEntryResponse](#datastore.FetchNodeResolverMapEntryResponse)
  
    * [FetchRegistrationEntryRequest](#datastore.FetchRegistrationEntryRequest)
  
    * [FetchRegistrationEntryResponse](#datastore.FetchRegistrationEntryResponse)
  
    * [FetchStaleNodeEntriesRequest](#datastore.FetchStaleNodeEntriesRequest)
  
    * [FetchStaleNodeEntriesResponse](#datastore.FetchStaleNodeEntriesResponse)
  
    * [ListFederatedEntryRequest](#datastore.ListFederatedEntryRequest)
  
    * [ListFederatedEntryResponse](#datastore.ListFederatedEntryResponse)
  
    * [ListParentIDEntriesRequest](#datastore.ListParentIDEntriesRequest)
  
    * [ListParentIDEntriesResponse](#datastore.ListParentIDEntriesResponse)
  
    * [ListSelectorEntriesRequest](#datastore.ListSelectorEntriesRequest)
  
    * [ListSelectorEntriesResponse](#datastore.ListSelectorEntriesResponse)
  
    * [ListSpiffeEntriesRequest](#datastore.ListSpiffeEntriesRequest)
  
    * [ListSpiffeEntriesResponse](#datastore.ListSpiffeEntriesResponse)
  
    * [NodeResolverMapEntry](#datastore.NodeResolverMapEntry)
  
    * [RectifyNodeResolverMapEntriesRequest](#datastore.RectifyNodeResolverMapEntriesRequest)
  
    * [RectifyNodeResolverMapEntriesResponse](#datastore.RectifyNodeResolverMapEntriesResponse)
  
    * [UpdateAttestedNodeEntryRequest](#datastore.UpdateAttestedNodeEntryRequest)
  
    * [UpdateAttestedNodeEntryResponse](#datastore.UpdateAttestedNodeEntryResponse)
  
    * [UpdateFederatedEntryRequest](#datastore.UpdateFederatedEntryRequest)
  
    * [UpdateFederatedEntryResponse](#datastore.UpdateFederatedEntryResponse)
  
    * [UpdateRegistrationEntryRequest](#datastore.UpdateRegistrationEntryRequest)
  
    * [UpdateRegistrationEntryResponse](#datastore.UpdateRegistrationEntryResponse)
  
  
  
  
    * [DataStore](#datastore.DataStore)
  

* [Scalar Value Types](#scalar-value-types)



<a name="plugin.proto"/>
<p align="right"><a href="#top">Top</a></p>

## plugin.proto



<a name="sriplugin.ConfigureRequest"/>

### ConfigureRequest
Represents the plugin-specific configuration string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| configuration | [string](#string) |  | The configuration for the plugin. |






<a name="sriplugin.ConfigureResponse"/>

### ConfigureResponse
Represents a list of configuration problems found in the configuration string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| errorList | [string](#string) | repeated | A list of errors. |






<a name="sriplugin.GetPluginInfoRequest"/>

### GetPluginInfoRequest
Represents an empty request.






<a name="sriplugin.GetPluginInfoResponse"/>

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






<a name="sriplugin.PluginInfoReply"/>

### PluginInfoReply



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| pluginInfo | [GetPluginInfoResponse](#sriplugin.GetPluginInfoResponse) | repeated |  |






<a name="sriplugin.PluginInfoRequest"/>

### PluginInfoRequest







<a name="sriplugin.StopReply"/>

### StopReply







<a name="sriplugin.StopRequest"/>

### StopRequest






 

 

 


<a name="sriplugin.Server"/>

### Server


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Stop | [StopRequest](#sriplugin.StopRequest) | [StopReply](#sriplugin.StopRequest) |  |
| PluginInfo | [PluginInfoRequest](#sriplugin.PluginInfoRequest) | [PluginInfoReply](#sriplugin.PluginInfoRequest) |  |

 



<a name="common.proto"/>
<p align="right"><a href="#top">Top</a></p>

## common.proto



<a name="common.AttestedData"/>

### AttestedData
A type which contains attestation data for specific platform.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [string](#string) |  | Type of attestation to perform. |
| data | [bytes](#bytes) |  | The attestetion data. |






<a name="common.Empty"/>

### Empty
Represents an empty message






<a name="common.RegistrationEntries"/>

### RegistrationEntries
A list of registration entries.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entries | [RegistrationEntry](#common.RegistrationEntry) | repeated | A list of RegistrationEntry. |






<a name="common.RegistrationEntry"/>

### RegistrationEntry
This is a curated record that the Control Plane uses to set up and manage the various registered nodes and workloads that are controlled by it.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectors | [Selector](#common.Selector) | repeated | A list of selectors. |
| parent_id | [string](#string) |  | The SPIFFE ID of an entity that is authorized to attest the validity of a selector |
| spiffe_id | [string](#string) |  | The SPIFFE ID is a structured string used to identify a resource or caller. It is defined as a URI comprising a “trust domain” and an associated path. |
| ttl | [int32](#int32) |  | Time to live. |
| fb_spiffe_ids | [string](#string) | repeated | A list of federated bundle spiffe ids. |






<a name="common.Selector"/>

### Selector
A type which describes the conditions under which a registration entry is matched.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [string](#string) |  | A selector type represents the type of attestation used in attesting the entity (Eg: AWS, K8). |
| value | [string](#string) |  | The value to be attested. |






<a name="common.Selectors"/>

### Selectors
Represents a type with a list of NodeResolution.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entries | [Selector](#common.Selector) | repeated | A list of NodeResolution. |





 

 

 

 



<a name="data_store.proto"/>
<p align="right"><a href="#top">Top</a></p>

## data_store.proto



<a name="datastore.AttestedNodeEntry"/>

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






<a name="datastore.CreateAttestedNodeEntryRequest"/>

### CreateAttestedNodeEntryRequest
Represents an Attested Node entry to create


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#datastore.AttestedNodeEntry) |  | Attested node entry |






<a name="datastore.CreateAttestedNodeEntryResponse"/>

### CreateAttestedNodeEntryResponse
Represents the created Attested Node entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#datastore.AttestedNodeEntry) |  | Attested node entry |






<a name="datastore.CreateFederatedEntryRequest"/>

### CreateFederatedEntryRequest
Represents a Federated bundle


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#datastore.FederatedBundle) |  | Federated bundle |






<a name="datastore.CreateFederatedEntryResponse"/>

### CreateFederatedEntryResponse
Empty






<a name="datastore.CreateNodeResolverMapEntryRequest"/>

### CreateNodeResolverMapEntryRequest
Represents a Node resolver map entry to create


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntry | [NodeResolverMapEntry](#datastore.NodeResolverMapEntry) |  | Node resolver map entry |






<a name="datastore.CreateNodeResolverMapEntryResponse"/>

### CreateNodeResolverMapEntryResponse
Represents the created Node resolver map entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntry | [NodeResolverMapEntry](#datastore.NodeResolverMapEntry) |  | Node resolver map entry |






<a name="datastore.CreateRegistrationEntryRequest"/>

### CreateRegistrationEntryRequest
Represents a Registration entry to create


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [.common.RegistrationEntry](#datastore..common.RegistrationEntry) |  | Registration entry |






<a name="datastore.CreateRegistrationEntryResponse"/>

### CreateRegistrationEntryResponse
Represents the created Registration entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryId | [string](#string) |  | Registration entry ID |






<a name="datastore.DeleteAttestedNodeEntryRequest"/>

### DeleteAttestedNodeEntryRequest
Represents the Spiffe ID of the Attested node entry to delete


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | SPIFFE ID |






<a name="datastore.DeleteAttestedNodeEntryResponse"/>

### DeleteAttestedNodeEntryResponse
Represents the deleted Attested node entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#datastore.AttestedNodeEntry) |  |  |






<a name="datastore.DeleteFederatedEntryRequest"/>

### DeleteFederatedEntryRequest
Represents the Spiffe ID of the federated bundle to delete


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundleSpiffeId | [string](#string) |  | SPIFFE ID of foreign trust domain |






<a name="datastore.DeleteFederatedEntryResponse"/>

### DeleteFederatedEntryResponse
Represents the deleted federated bundle


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#datastore.FederatedBundle) |  | Federated bundle |






<a name="datastore.DeleteNodeResolverMapEntryRequest"/>

### DeleteNodeResolverMapEntryRequest
Represents a Node resolver map entry to delete


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntry | [NodeResolverMapEntry](#datastore.NodeResolverMapEntry) |  | Node resolver map entry |






<a name="datastore.DeleteNodeResolverMapEntryResponse"/>

### DeleteNodeResolverMapEntryResponse
Represents a list of Node resolver map entries


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntryList | [NodeResolverMapEntry](#datastore.NodeResolverMapEntry) | repeated | List of Node resolver map entries |






<a name="datastore.DeleteRegistrationEntryRequest"/>

### DeleteRegistrationEntryRequest
Represents a Registration entry ID to delete


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryId | [string](#string) |  | Registration entry ID |






<a name="datastore.DeleteRegistrationEntryResponse"/>

### DeleteRegistrationEntryResponse
Represents the deleted Registration entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [.common.RegistrationEntry](#datastore..common.RegistrationEntry) |  | Registration entry |






<a name="datastore.FederatedBundle"/>

### FederatedBundle
Represents the trust chain for a different trust domain, along with
a TTL describing its expiration, keyed by the SPIFFE ID of the foreign
trust domain.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundleSpiffeId | [string](#string) |  | Foreign trust domain SPIFFE ID |
| federatedTrustBundle | [bytes](#bytes) |  | Trust chain |
| ttl | [int32](#int32) |  | TTL |






<a name="datastore.FetchAttestedNodeEntryRequest"/>

### FetchAttestedNodeEntryRequest
Represents the Spiffe ID of the node entry to retrieve


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | SPIFFE ID |






<a name="datastore.FetchAttestedNodeEntryResponse"/>

### FetchAttestedNodeEntryResponse
Represents an Attested Node entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#datastore.AttestedNodeEntry) |  | Attested node entry |






<a name="datastore.FetchNodeResolverMapEntryRequest"/>

### FetchNodeResolverMapEntryRequest
Represents a Spiffe ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | SPIFFE ID |






<a name="datastore.FetchNodeResolverMapEntryResponse"/>

### FetchNodeResolverMapEntryResponse
Represents a list of Node resolver map entries for the specified Spiffe ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntryList | [NodeResolverMapEntry](#datastore.NodeResolverMapEntry) | repeated | List of Node resolver map entries |






<a name="datastore.FetchRegistrationEntryRequest"/>

### FetchRegistrationEntryRequest
Represents a Registration entry ID to fetch


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryId | [string](#string) |  | Registration entry ID |






<a name="datastore.FetchRegistrationEntryResponse"/>

### FetchRegistrationEntryResponse
Represents a Registration entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [.common.RegistrationEntry](#datastore..common.RegistrationEntry) |  | Registration entry |






<a name="datastore.FetchStaleNodeEntriesRequest"/>

### FetchStaleNodeEntriesRequest
Empty






<a name="datastore.FetchStaleNodeEntriesResponse"/>

### FetchStaleNodeEntriesResponse
Represents dead nodes for which the base SVID has expired


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntryList | [AttestedNodeEntry](#datastore.AttestedNodeEntry) | repeated | List of attested node entries |






<a name="datastore.ListFederatedEntryRequest"/>

### ListFederatedEntryRequest
Empty






<a name="datastore.ListFederatedEntryResponse"/>

### ListFederatedEntryResponse
Represents a list of SPIFFE IDs of foreign trust domains


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundleSpiffeIdList | [string](#string) | repeated | SPIFFE IDs of foreign trust domains |






<a name="datastore.ListParentIDEntriesRequest"/>

### ListParentIDEntriesRequest
Represents a Parent ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| parentId | [string](#string) |  | Parent ID |






<a name="datastore.ListParentIDEntriesResponse"/>

### ListParentIDEntriesResponse
Represents a list of Registered entries with the specified Parent ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryList | [.common.RegistrationEntry](#datastore..common.RegistrationEntry) | repeated | List of Registration entries |






<a name="datastore.ListSelectorEntriesRequest"/>

### ListSelectorEntriesRequest
Represents a selector


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selector | [.common.Selector](#datastore..common.Selector) |  | Selector |






<a name="datastore.ListSelectorEntriesResponse"/>

### ListSelectorEntriesResponse
Represents a list of Registered entries with the specified selector


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryList | [.common.RegistrationEntry](#datastore..common.RegistrationEntry) | repeated | List of Registration entries |






<a name="datastore.ListSpiffeEntriesRequest"/>

### ListSpiffeEntriesRequest
Represents a Spiffe ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeId | [string](#string) |  | Spiffe ID |






<a name="datastore.ListSpiffeEntriesResponse"/>

### ListSpiffeEntriesResponse
Represents a list of Registered entries with the specified Spiffe ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryList | [.common.RegistrationEntry](#datastore..common.RegistrationEntry) | repeated | List of Registration entries |






<a name="datastore.NodeResolverMapEntry"/>

### NodeResolverMapEntry
Represents a single entry in NodeResolverMap and maps node properties to
logical attributes (i.e. an AWS instance to its ASG).


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  |  |
| selector | [.common.Selector](#datastore..common.Selector) |  |  |






<a name="datastore.RectifyNodeResolverMapEntriesRequest"/>

### RectifyNodeResolverMapEntriesRequest
Represents a list of Node resolver map entries


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntryList | [NodeResolverMapEntry](#datastore.NodeResolverMapEntry) | repeated | List of Node resolver map entries |






<a name="datastore.RectifyNodeResolverMapEntriesResponse"/>

### RectifyNodeResolverMapEntriesResponse
Represents a list of Node resolver map entries


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodeResolverMapEntryList | [NodeResolverMapEntry](#datastore.NodeResolverMapEntry) | repeated | List of Node resolver map entries |






<a name="datastore.UpdateAttestedNodeEntryRequest"/>

### UpdateAttestedNodeEntryRequest
Represents Attested node entry fields to update


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeId | [string](#string) |  | Spiffe ID |
| certSerialNumber | [string](#string) |  | Serial number |
| certExpirationDate | [string](#string) |  | Expiration date |






<a name="datastore.UpdateAttestedNodeEntryResponse"/>

### UpdateAttestedNodeEntryResponse
Represents the updated Attested node entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedNodeEntry | [AttestedNodeEntry](#datastore.AttestedNodeEntry) |  | Attested node entry |






<a name="datastore.UpdateFederatedEntryRequest"/>

### UpdateFederatedEntryRequest
Represents a federated bundle to update


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#datastore.FederatedBundle) |  | Federated bundle |






<a name="datastore.UpdateFederatedEntryResponse"/>

### UpdateFederatedEntryResponse
Represents the updated federated bundle


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federatedBundle | [FederatedBundle](#datastore.FederatedBundle) |  | Federated bundle |






<a name="datastore.UpdateRegistrationEntryRequest"/>

### UpdateRegistrationEntryRequest
Represents a Registration entry to update


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntryId | [string](#string) |  | Registration entry ID |
| registeredEntry | [.common.RegistrationEntry](#datastore..common.RegistrationEntry) |  | Registration entry |






<a name="datastore.UpdateRegistrationEntryResponse"/>

### UpdateRegistrationEntryResponse
Represents the updated Registration entry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| registeredEntry | [.common.RegistrationEntry](#datastore..common.RegistrationEntry) |  | Registration entry |





 

 

 


<a name="datastore.DataStore"/>

### DataStore


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| CreateFederatedEntry | [CreateFederatedEntryRequest](#datastore.CreateFederatedEntryRequest) | [CreateFederatedEntryResponse](#datastore.CreateFederatedEntryRequest) | Creates a Federated Bundle |
| ListFederatedEntry | [ListFederatedEntryRequest](#datastore.ListFederatedEntryRequest) | [ListFederatedEntryResponse](#datastore.ListFederatedEntryRequest) | List all Federated SPIFFE IDs |
| UpdateFederatedEntry | [UpdateFederatedEntryRequest](#datastore.UpdateFederatedEntryRequest) | [UpdateFederatedEntryResponse](#datastore.UpdateFederatedEntryRequest) | Updates the specified Federated Bundle |
| DeleteFederatedEntry | [DeleteFederatedEntryRequest](#datastore.DeleteFederatedEntryRequest) | [DeleteFederatedEntryResponse](#datastore.DeleteFederatedEntryRequest) | Deletes the specified Federated Bundle |
| CreateAttestedNodeEntry | [CreateAttestedNodeEntryRequest](#datastore.CreateAttestedNodeEntryRequest) | [CreateAttestedNodeEntryResponse](#datastore.CreateAttestedNodeEntryRequest) | Creates an Attested Node Entry |
| FetchAttestedNodeEntry | [FetchAttestedNodeEntryRequest](#datastore.FetchAttestedNodeEntryRequest) | [FetchAttestedNodeEntryResponse](#datastore.FetchAttestedNodeEntryRequest) | Retrieves the Attested Node Entry |
| FetchStaleNodeEntries | [FetchStaleNodeEntriesRequest](#datastore.FetchStaleNodeEntriesRequest) | [FetchStaleNodeEntriesResponse](#datastore.FetchStaleNodeEntriesRequest) | Retrieves dead nodes for which the base SVID has expired |
| UpdateAttestedNodeEntry | [UpdateAttestedNodeEntryRequest](#datastore.UpdateAttestedNodeEntryRequest) | [UpdateAttestedNodeEntryResponse](#datastore.UpdateAttestedNodeEntryRequest) | Updates the Attested Node Entry |
| DeleteAttestedNodeEntry | [DeleteAttestedNodeEntryRequest](#datastore.DeleteAttestedNodeEntryRequest) | [DeleteAttestedNodeEntryResponse](#datastore.DeleteAttestedNodeEntryRequest) | Deletes the Attested Node Entry |
| CreateNodeResolverMapEntry | [CreateNodeResolverMapEntryRequest](#datastore.CreateNodeResolverMapEntryRequest) | [CreateNodeResolverMapEntryResponse](#datastore.CreateNodeResolverMapEntryRequest) | Creates a Node resolver map Entry |
| FetchNodeResolverMapEntry | [FetchNodeResolverMapEntryRequest](#datastore.FetchNodeResolverMapEntryRequest) | [FetchNodeResolverMapEntryResponse](#datastore.FetchNodeResolverMapEntryRequest) | Retrieves all Node Resolver Map Entry for the specific base SPIFFEID |
| DeleteNodeResolverMapEntry | [DeleteNodeResolverMapEntryRequest](#datastore.DeleteNodeResolverMapEntryRequest) | [DeleteNodeResolverMapEntryResponse](#datastore.DeleteNodeResolverMapEntryRequest) | Deletes all Node Resolver Map Entry for the specific base SPIFFEID |
| RectifyNodeResolverMapEntries | [RectifyNodeResolverMapEntriesRequest](#datastore.RectifyNodeResolverMapEntriesRequest) | [RectifyNodeResolverMapEntriesResponse](#datastore.RectifyNodeResolverMapEntriesRequest) | Used for rectifying updated node resolutions |
| CreateRegistrationEntry | [CreateRegistrationEntryRequest](#datastore.CreateRegistrationEntryRequest) | [CreateRegistrationEntryResponse](#datastore.CreateRegistrationEntryRequest) | Creates a Registered Entry |
| FetchRegistrationEntry | [FetchRegistrationEntryRequest](#datastore.FetchRegistrationEntryRequest) | [FetchRegistrationEntryResponse](#datastore.FetchRegistrationEntryRequest) | Retrieve a specific registered entry |
| UpdateRegistrationEntry | [UpdateRegistrationEntryRequest](#datastore.UpdateRegistrationEntryRequest) | [UpdateRegistrationEntryResponse](#datastore.UpdateRegistrationEntryRequest) | Updates a specific registered entry |
| DeleteRegistrationEntry | [DeleteRegistrationEntryRequest](#datastore.DeleteRegistrationEntryRequest) | [DeleteRegistrationEntryResponse](#datastore.DeleteRegistrationEntryRequest) | Deletes a specific registered entry |
| ListParentIDEntries | [ListParentIDEntriesRequest](#datastore.ListParentIDEntriesRequest) | [ListParentIDEntriesResponse](#datastore.ListParentIDEntriesRequest) | Retrieves all the  registered entry with the same ParentID |
| ListSelectorEntries | [ListSelectorEntriesRequest](#datastore.ListSelectorEntriesRequest) | [ListSelectorEntriesResponse](#datastore.ListSelectorEntriesRequest) | Retrieves all the  registered entry with the same Selector |
| ListSpiffeEntries | [ListSpiffeEntriesRequest](#datastore.ListSpiffeEntriesRequest) | [ListSpiffeEntriesResponse](#datastore.ListSpiffeEntriesRequest) | Retrieves all the  registered entry with the same SpiffeId |
| Configure | [sriplugin.ConfigureRequest](#sriplugin.ConfigureRequest) | [sriplugin.ConfigureResponse](#sriplugin.ConfigureRequest) | Applies the plugin configuration |
| GetPluginInfo | [sriplugin.GetPluginInfoRequest](#sriplugin.GetPluginInfoRequest) | [sriplugin.GetPluginInfoResponse](#sriplugin.GetPluginInfoRequest) | Returns the version and related metadata of the installed plugin |

 



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

