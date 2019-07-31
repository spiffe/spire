# Protocol Documentation
<a name="top"/>

## Table of Contents

- [common.proto](#common.proto)
    - [AttestationData](#spire.common.AttestationData)
    - [AttestedNode](#spire.common.AttestedNode)
    - [Bundle](#spire.common.Bundle)
    - [Certificate](#spire.common.Certificate)
    - [Empty](#spire.common.Empty)
    - [PublicKey](#spire.common.PublicKey)
    - [RegistrationEntries](#spire.common.RegistrationEntries)
    - [RegistrationEntry](#spire.common.RegistrationEntry)
    - [Selector](#spire.common.Selector)
    - [Selectors](#spire.common.Selectors)
  
  
  
  

- [registration.proto](#registration.proto)
    - [Bundle](#spire.api.registration.Bundle)
    - [DeleteFederatedBundleRequest](#spire.api.registration.DeleteFederatedBundleRequest)
    - [EvictAgentRequest](#spire.api.registration.EvictAgentRequest)
    - [EvictAgentResponse](#spire.api.registration.EvictAgentResponse)
    - [FederatedBundle](#spire.api.registration.FederatedBundle)
    - [FederatedBundleID](#spire.api.registration.FederatedBundleID)
    - [JoinToken](#spire.api.registration.JoinToken)
    - [ListAgentsRequest](#spire.api.registration.ListAgentsRequest)
    - [ListAgentsResponse](#spire.api.registration.ListAgentsResponse)
    - [ParentID](#spire.api.registration.ParentID)
    - [RegistrationEntryID](#spire.api.registration.RegistrationEntryID)
    - [SpiffeID](#spire.api.registration.SpiffeID)
    - [UpdateEntryRequest](#spire.api.registration.UpdateEntryRequest)
  
    - [DeleteFederatedBundleRequest.Mode](#spire.api.registration.DeleteFederatedBundleRequest.Mode)
  
  
    - [Registration](#spire.api.registration.Registration)
  

- [Scalar Value Types](#scalar-value-types)



<a name="common.proto"/>
<p align="right"><a href="#top">Top</a></p>

## common.proto



<a name="spire.common.AttestationData"/>

### AttestationData
A type which contains attestation data for specific platform.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [string](#string) |  | Type of attestation to perform. |
| data | [bytes](#bytes) |  | The attestation data. |






<a name="spire.common.AttestedNode"/>

### AttestedNode
Represents an attested SPIRE agent


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  | Node SPIFFE ID |
| attestation_data_type | [string](#string) |  | Attestation data type |
| cert_serial_number | [string](#string) |  | Node certificate serial number |
| cert_not_after | [int64](#int64) |  | Node certificate not_after (seconds since unix epoch) |






<a name="spire.common.Bundle"/>

### Bundle



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| trust_domain_id | [string](#string) |  | the SPIFFE ID of the trust domain the bundle belongs to |
| root_cas | [Certificate](#spire.common.Certificate) | repeated | list of root CA certificates |
| jwt_signing_keys | [PublicKey](#spire.common.PublicKey) | repeated | list of JWT signing keys |
| refresh_hint | [int64](#int64) |  | refresh hint is a hint, in seconds, on how often a bundle consumer should poll for bundle updates |






<a name="spire.common.Certificate"/>

### Certificate
Certificate represents a ASN.1/DER encoded X509 certificate


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| der_bytes | [bytes](#bytes) |  |  |






<a name="spire.common.Empty"/>

### Empty
Represents an empty message






<a name="spire.common.PublicKey"/>

### PublicKey
PublicKey represents a PKIX encoded public key


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| pkix_bytes | [bytes](#bytes) |  | PKIX encoded key data |
| kid | [string](#string) |  | key identifier |
| not_after | [int64](#int64) |  | not after (seconds since unix epoch, 0 means &#34;never expires&#34;) |






<a name="spire.common.RegistrationEntries"/>

### RegistrationEntries
A list of registration entries.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entries | [RegistrationEntry](#spire.common.RegistrationEntry) | repeated | A list of RegistrationEntry. |






<a name="spire.common.RegistrationEntry"/>

### RegistrationEntry
This is a curated record that the Server uses to set up and
manage the various registered nodes and workloads that are controlled by it.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectors | [Selector](#spire.common.Selector) | repeated | A list of selectors. |
| parent_id | [string](#string) |  | The SPIFFE ID of an entity that is authorized to attest the validity of a selector |
| spiffe_id | [string](#string) |  | The SPIFFE ID is a structured string used to identify a resource or caller. It is defined as a URI comprising a “trust domain” and an associated path. |
| ttl | [int32](#int32) |  | Time to live. |
| federates_with | [string](#string) | repeated | A list of federated trust domain SPIFFE IDs. |
| entry_id | [string](#string) |  | Entry ID |
| admin | [bool](#bool) |  | Whether or not the workload is an admin workload. Admin workloads can use their SVID&#39;s to authenticate with the Registration API, for example. |
| downstream | [bool](#bool) |  | To enable signing CA CSR in upstream spire server |
| entryExpiry | [int64](#int64) |  | Expiration of this entry, in seconds from epoch |
| dns_names | [string](#string) | repeated | DNS entries |
| registrant_id | [string](#string) |  | SPIFFE ID of the workload that created this registration entry |






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
Represents a type with a list of Selector.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entries | [Selector](#spire.common.Selector) | repeated | A list of Selector. |





 

 

 

 



<a name="registration.proto"/>
<p align="right"><a href="#top">Top</a></p>

## registration.proto



<a name="spire.api.registration.Bundle"/>

### Bundle
CA Bundle of the server


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [.spire.common.Bundle](#spire.api.registration..spire.common.Bundle) |  | Common bundle format |






<a name="spire.api.registration.DeleteFederatedBundleRequest"/>

### DeleteFederatedBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  |  |
| mode | [DeleteFederatedBundleRequest.Mode](#spire.api.registration.DeleteFederatedBundleRequest.Mode) |  |  |






<a name="spire.api.registration.EvictAgentRequest"/>

### EvictAgentRequest
Represents an evict request


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeID | [string](#string) |  | Agent identity of the node to be evicted. For example: &#34;spiffe://example.org/spire/agent/join_token/feea6adc-3254-4052-9a18-5eeb74bf214f&#34; |






<a name="spire.api.registration.EvictAgentResponse"/>

### EvictAgentResponse
Represents an evict response


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| node | [.spire.common.AttestedNode](#spire.api.registration..spire.common.AttestedNode) |  | Node contains the evicted node |






<a name="spire.api.registration.FederatedBundle"/>

### FederatedBundle
A CA bundle for a different Trust Domain than the one used and managed by the Server.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [.spire.common.Bundle](#spire.api.registration..spire.common.Bundle) |  | Common bundle format |






<a name="spire.api.registration.FederatedBundleID"/>

### FederatedBundleID
A type that represents a federated bundle id.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | SPIFFE ID of the federated bundle |






<a name="spire.api.registration.JoinToken"/>

### JoinToken
JoinToken message is used for registering a new token


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| token | [string](#string) |  | The join token. If not set, one will be generated |
| ttl | [int32](#int32) |  | TTL in seconds |






<a name="spire.api.registration.ListAgentsRequest"/>

### ListAgentsRequest
Represents a ListAgents request






<a name="spire.api.registration.ListAgentsResponse"/>

### ListAgentsResponse
Represents a ListAgents response


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodes | [.spire.common.AttestedNode](#spire.api.registration..spire.common.AttestedNode) | repeated | List of all attested agents |






<a name="spire.api.registration.ParentID"/>

### ParentID
A type that represents a parent Id.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | ParentId. |






<a name="spire.api.registration.RegistrationEntryID"/>

### RegistrationEntryID
A type that represents the id of an entry.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | RegistrationEntryID. |






<a name="spire.api.registration.SpiffeID"/>

### SpiffeID
A type that represents a SPIFFE Id.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | SpiffeId. |






<a name="spire.api.registration.UpdateEntryRequest"/>

### UpdateEntryRequest
A type used to update registration entries


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry | [.spire.common.RegistrationEntry](#spire.api.registration..spire.common.RegistrationEntry) |  | Registration entry to update |





 


<a name="spire.api.registration.DeleteFederatedBundleRequest.Mode"/>

### DeleteFederatedBundleRequest.Mode
Mode controls the delete behavior if there are other records
associated with the bundle (e.g. registration entries).

| Name | Number | Description |
| ---- | ------ | ----------- |
| RESTRICT | 0 | RESTRICT prevents the bundle from being deleted in the presence of associated entries |
| DELETE | 1 | DELETE deletes the bundle and associated entries |
| DISSOCIATE | 2 | DISSOCIATE deletes the bundle and dissociates associated entries |


 

 


<a name="spire.api.registration.Registration"/>

### Registration


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| CreateEntry | [spire.common.RegistrationEntry](#spire.common.RegistrationEntry) | [RegistrationEntryID](#spire.common.RegistrationEntry) | Creates an entry in the Registration table, used to assign SPIFFE IDs to nodes and workloads. |
| DeleteEntry | [RegistrationEntryID](#spire.api.registration.RegistrationEntryID) | [spire.common.RegistrationEntry](#spire.api.registration.RegistrationEntryID) | Deletes an entry and returns the deleted entry. |
| FetchEntry | [RegistrationEntryID](#spire.api.registration.RegistrationEntryID) | [spire.common.RegistrationEntry](#spire.api.registration.RegistrationEntryID) | Retrieve a specific registered entry. |
| FetchEntries | [spire.common.Empty](#spire.common.Empty) | [spire.common.RegistrationEntries](#spire.common.Empty) | Retrieve all registered entries. |
| UpdateEntry | [UpdateEntryRequest](#spire.api.registration.UpdateEntryRequest) | [spire.common.RegistrationEntry](#spire.api.registration.UpdateEntryRequest) | Updates a specific registered entry. |
| ListByParentID | [ParentID](#spire.api.registration.ParentID) | [spire.common.RegistrationEntries](#spire.api.registration.ParentID) | Returns all the Entries associated with the ParentID value. |
| ListBySelector | [spire.common.Selector](#spire.common.Selector) | [spire.common.RegistrationEntries](#spire.common.Selector) | Returns all the entries associated with a selector value. |
| ListBySelectors | [spire.common.Selectors](#spire.common.Selectors) | [spire.common.RegistrationEntries](#spire.common.Selectors) | Returns all the entries matching the set of selectors |
| ListBySpiffeID | [SpiffeID](#spire.api.registration.SpiffeID) | [spire.common.RegistrationEntries](#spire.api.registration.SpiffeID) | Return all registration entries for which SPIFFE ID matches. |
| ListByRegistrantID | [SpiffeID](#spire.api.registration.SpiffeID) | [spire.common.RegistrationEntries](#spire.api.registration.SpiffeID) | Return all registration entries that were registered by a workload with the provided SPIFFE ID. |
| CreateFederatedBundle | [FederatedBundle](#spire.api.registration.FederatedBundle) | [spire.common.Empty](#spire.api.registration.FederatedBundle) | Creates an entry in the Federated bundle table to store the mappings of Federated SPIFFE IDs and their associated CA bundle. |
| FetchFederatedBundle | [FederatedBundleID](#spire.api.registration.FederatedBundleID) | [FederatedBundle](#spire.api.registration.FederatedBundleID) | Retrieves a single federated bundle |
| ListFederatedBundles | [spire.common.Empty](#spire.common.Empty) | [FederatedBundle](#spire.common.Empty) | Retrieves Federated bundles for all the Federated SPIFFE IDs. |
| UpdateFederatedBundle | [FederatedBundle](#spire.api.registration.FederatedBundle) | [spire.common.Empty](#spire.api.registration.FederatedBundle) | Updates a particular Federated Bundle. Useful for rotation. |
| DeleteFederatedBundle | [DeleteFederatedBundleRequest](#spire.api.registration.DeleteFederatedBundleRequest) | [spire.common.Empty](#spire.api.registration.DeleteFederatedBundleRequest) | Delete a particular Federated Bundle. Used to destroy inter-domain trust. |
| CreateJoinToken | [JoinToken](#spire.api.registration.JoinToken) | [JoinToken](#spire.api.registration.JoinToken) | Create a new join token |
| FetchBundle | [spire.common.Empty](#spire.common.Empty) | [Bundle](#spire.common.Empty) | Retrieves the CA bundle. |
| EvictAgent | [EvictAgentRequest](#spire.api.registration.EvictAgentRequest) | [EvictAgentResponse](#spire.api.registration.EvictAgentRequest) | EvictAgent removes an attestation entry from the attested nodes store |
| ListAgents | [ListAgentsRequest](#spire.api.registration.ListAgentsRequest) | [ListAgentsResponse](#spire.api.registration.ListAgentsRequest) | ListAgents will list all attested nodes |

 



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

