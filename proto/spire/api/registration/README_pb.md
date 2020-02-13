# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [registration.proto](#registration.proto)
    - [Bundle](#spire.api.registration.Bundle)
    - [DeleteFederatedBundleRequest](#spire.api.registration.DeleteFederatedBundleRequest)
    - [EvictAgentRequest](#spire.api.registration.EvictAgentRequest)
    - [EvictAgentResponse](#spire.api.registration.EvictAgentResponse)
    - [FederatedBundle](#spire.api.registration.FederatedBundle)
    - [FederatedBundleID](#spire.api.registration.FederatedBundleID)
    - [GetNodeSelectorsRequest](#spire.api.registration.GetNodeSelectorsRequest)
    - [GetNodeSelectorsResponse](#spire.api.registration.GetNodeSelectorsResponse)
    - [JoinToken](#spire.api.registration.JoinToken)
    - [ListAgentsRequest](#spire.api.registration.ListAgentsRequest)
    - [ListAgentsResponse](#spire.api.registration.ListAgentsResponse)
    - [ListAllEntriesRequest](#spire.api.registration.ListAllEntriesRequest)
    - [ListAllEntriesResponse](#spire.api.registration.ListAllEntriesResponse)
    - [MintJWTSVIDRequest](#spire.api.registration.MintJWTSVIDRequest)
    - [MintJWTSVIDResponse](#spire.api.registration.MintJWTSVIDResponse)
    - [MintX509SVIDRequest](#spire.api.registration.MintX509SVIDRequest)
    - [MintX509SVIDResponse](#spire.api.registration.MintX509SVIDResponse)
    - [NodeSelectors](#spire.api.registration.NodeSelectors)
    - [Pagination](#spire.api.registration.Pagination)
    - [ParentID](#spire.api.registration.ParentID)
    - [RegistrationEntryID](#spire.api.registration.RegistrationEntryID)
    - [SpiffeID](#spire.api.registration.SpiffeID)
    - [UpdateEntryRequest](#spire.api.registration.UpdateEntryRequest)
  
    - [DeleteFederatedBundleRequest.Mode](#spire.api.registration.DeleteFederatedBundleRequest.Mode)
  
  
    - [Registration](#spire.api.registration.Registration)
  

- [Scalar Value Types](#scalar-value-types)



<a name="registration.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## registration.proto



<a name="spire.api.registration.Bundle"></a>

### Bundle
CA Bundle of the server


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [spire.common.Bundle](#spire.common.Bundle) |  | Common bundle format |






<a name="spire.api.registration.DeleteFederatedBundleRequest"></a>

### DeleteFederatedBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  |  |
| mode | [DeleteFederatedBundleRequest.Mode](#spire.api.registration.DeleteFederatedBundleRequest.Mode) |  |  |






<a name="spire.api.registration.EvictAgentRequest"></a>

### EvictAgentRequest
Represents an evict request


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeID | [string](#string) |  | Agent identity of the node to be evicted. For example: &#34;spiffe://example.org/spire/agent/join_token/feea6adc-3254-4052-9a18-5eeb74bf214f&#34; |






<a name="spire.api.registration.EvictAgentResponse"></a>

### EvictAgentResponse
Represents an evict response


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| node | [spire.common.AttestedNode](#spire.common.AttestedNode) |  | Node contains the evicted node |






<a name="spire.api.registration.FederatedBundle"></a>

### FederatedBundle
A CA bundle for a different Trust Domain than the one used and managed by the Server.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [spire.common.Bundle](#spire.common.Bundle) |  | Common bundle format |






<a name="spire.api.registration.FederatedBundleID"></a>

### FederatedBundleID
A type that represents a federated bundle id.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | SPIFFE ID of the federated bundle |






<a name="spire.api.registration.GetNodeSelectorsRequest"></a>

### GetNodeSelectorsRequest
Represents a GetNodeSelectors request


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  |  |






<a name="spire.api.registration.GetNodeSelectorsResponse"></a>

### GetNodeSelectorsResponse
Represents a GetNodeSelectors response


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectors | [NodeSelectors](#spire.api.registration.NodeSelectors) |  |  |






<a name="spire.api.registration.JoinToken"></a>

### JoinToken
JoinToken message is used for registering a new token


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| token | [string](#string) |  | The join token. If not set, one will be generated |
| ttl | [int32](#int32) |  | TTL in seconds |






<a name="spire.api.registration.ListAgentsRequest"></a>

### ListAgentsRequest
Represents a ListAgents request






<a name="spire.api.registration.ListAgentsResponse"></a>

### ListAgentsResponse
Represents a ListAgents response


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodes | [spire.common.AttestedNode](#spire.common.AttestedNode) | repeated | List of all attested agents |






<a name="spire.api.registration.ListAllEntriesRequest"></a>

### ListAllEntriesRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| token | [string](#string) |  |  |
| page_size | [int32](#int32) |  |  |






<a name="spire.api.registration.ListAllEntriesResponse"></a>

### ListAllEntriesResponse
It is used to list all registration entries with pagination


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entries | [spire.common.RegistrationEntry](#spire.common.RegistrationEntry) | repeated |  |
| pagination | [Pagination](#spire.api.registration.Pagination) |  |  |






<a name="spire.api.registration.MintJWTSVIDRequest"></a>

### MintJWTSVIDRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  | SPIFFE ID of the JWT-SVID |
| ttl | [int32](#int32) |  | TTL of the JWT-SVID, in seconds. The server default will be used if unset. The TTL is advisory only. The actual lifetime of the JWT-SVID may be lower depending on the remaining lifetime of the active SPIRE Server CA. |
| audience | [string](#string) | repeated | List of audience claims to include in the JWT-SVID. At least one must be set. |






<a name="spire.api.registration.MintJWTSVIDResponse"></a>

### MintJWTSVIDResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| token | [string](#string) |  | JWT-SVID token |






<a name="spire.api.registration.MintX509SVIDRequest"></a>

### MintX509SVIDRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  | SPIFFE ID of the X509-SVID |
| csr | [bytes](#bytes) |  | ASN.1 encoded CSR. The CSR is only used to convey the public key and prove possession of the private key. The rest of the CSR is ignored. |
| ttl | [int32](#int32) |  | TTL of the X509-SVID, in seconds. The server default will be used if unset. The TTL is advisory only. The actual lifetime of the X509-SVID may be lower depending on the remaining lifetime of the active SPIRE Server CA. |
| dns_names | [string](#string) | repeated | DNS names to include as DNS SANs in the X509-SVID. If set, the first in the list is also set as the X509-SVID common name. |






<a name="spire.api.registration.MintX509SVIDResponse"></a>

### MintX509SVIDResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| svid_chain | [bytes](#bytes) | repeated | X509-SVID chain. This includes the X509-SVID itself and any intermediates necessary to chain back to certificates in the root_cas. |
| root_cas | [bytes](#bytes) | repeated | X.509 root certificates |






<a name="spire.api.registration.NodeSelectors"></a>

### NodeSelectors



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  | Node SPIFFE ID |
| selectors | [spire.common.Selector](#spire.common.Selector) | repeated | Node selectors |






<a name="spire.api.registration.Pagination"></a>

### Pagination
A type that represents pagination for list responses


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| token | [string](#string) |  |  |
| page_size | [int32](#int32) |  |  |






<a name="spire.api.registration.ParentID"></a>

### ParentID
A type that represents a parent Id.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | ParentId. |






<a name="spire.api.registration.RegistrationEntryID"></a>

### RegistrationEntryID
A type that represents the id of an entry.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | RegistrationEntryID. |






<a name="spire.api.registration.SpiffeID"></a>

### SpiffeID
A type that represents a SPIFFE Id.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | SpiffeId. |






<a name="spire.api.registration.UpdateEntryRequest"></a>

### UpdateEntryRequest
A type used to update registration entries


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry | [spire.common.RegistrationEntry](#spire.common.RegistrationEntry) |  | Registration entry to update |





 


<a name="spire.api.registration.DeleteFederatedBundleRequest.Mode"></a>

### DeleteFederatedBundleRequest.Mode
Mode controls the delete behavior if there are other records
associated with the bundle (e.g. registration entries).

| Name | Number | Description |
| ---- | ------ | ----------- |
| RESTRICT | 0 | RESTRICT prevents the bundle from being deleted in the presence of associated entries |
| DELETE | 1 | DELETE deletes the bundle and associated entries |
| DISSOCIATE | 2 | DISSOCIATE deletes the bundle and dissociates associated entries |


 

 


<a name="spire.api.registration.Registration"></a>

### Registration


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| CreateEntry | [.spire.common.RegistrationEntry](#spire.common.RegistrationEntry) | [RegistrationEntryID](#spire.api.registration.RegistrationEntryID) | Creates an entry in the Registration table, used to assign SPIFFE IDs to nodes and workloads. |
| DeleteEntry | [RegistrationEntryID](#spire.api.registration.RegistrationEntryID) | [.spire.common.RegistrationEntry](#spire.common.RegistrationEntry) | Deletes an entry and returns the deleted entry. |
| FetchEntry | [RegistrationEntryID](#spire.api.registration.RegistrationEntryID) | [.spire.common.RegistrationEntry](#spire.common.RegistrationEntry) | Retrieve a specific registered entry. |
| FetchEntries | [.spire.common.Empty](#spire.common.Empty) | [.spire.common.RegistrationEntries](#spire.common.RegistrationEntries) | Retrieve all registered entries. |
| UpdateEntry | [UpdateEntryRequest](#spire.api.registration.UpdateEntryRequest) | [.spire.common.RegistrationEntry](#spire.common.RegistrationEntry) | Updates a specific registered entry. |
| ListByParentID | [ParentID](#spire.api.registration.ParentID) | [.spire.common.RegistrationEntries](#spire.common.RegistrationEntries) | Returns all the Entries associated with the ParentID value. |
| ListBySelector | [.spire.common.Selector](#spire.common.Selector) | [.spire.common.RegistrationEntries](#spire.common.RegistrationEntries) | Returns all the entries associated with a selector value. |
| ListBySelectors | [.spire.common.Selectors](#spire.common.Selectors) | [.spire.common.RegistrationEntries](#spire.common.RegistrationEntries) | Returns all the entries matching the set of selectors |
| ListBySpiffeID | [SpiffeID](#spire.api.registration.SpiffeID) | [.spire.common.RegistrationEntries](#spire.common.RegistrationEntries) | Return all registration entries for which SPIFFE ID matches. |
| ListAllEntriesWithPages | [ListAllEntriesRequest](#spire.api.registration.ListAllEntriesRequest) | [ListAllEntriesResponse](#spire.api.registration.ListAllEntriesResponse) | Return all registration entries with pagination of default page size of 50. |
| CreateFederatedBundle | [FederatedBundle](#spire.api.registration.FederatedBundle) | [.spire.common.Empty](#spire.common.Empty) | Creates an entry in the Federated bundle table to store the mappings of Federated SPIFFE IDs and their associated CA bundle. |
| FetchFederatedBundle | [FederatedBundleID](#spire.api.registration.FederatedBundleID) | [FederatedBundle](#spire.api.registration.FederatedBundle) | Retrieves a single federated bundle |
| ListFederatedBundles | [.spire.common.Empty](#spire.common.Empty) | [FederatedBundle](#spire.api.registration.FederatedBundle) stream | Retrieves Federated bundles for all the Federated SPIFFE IDs. |
| UpdateFederatedBundle | [FederatedBundle](#spire.api.registration.FederatedBundle) | [.spire.common.Empty](#spire.common.Empty) | Updates a particular Federated Bundle. Useful for rotation. |
| DeleteFederatedBundle | [DeleteFederatedBundleRequest](#spire.api.registration.DeleteFederatedBundleRequest) | [.spire.common.Empty](#spire.common.Empty) | Delete a particular Federated Bundle. Used to destroy inter-domain trust. |
| CreateJoinToken | [JoinToken](#spire.api.registration.JoinToken) | [JoinToken](#spire.api.registration.JoinToken) | Create a new join token |
| FetchBundle | [.spire.common.Empty](#spire.common.Empty) | [Bundle](#spire.api.registration.Bundle) | Retrieves the CA bundle. |
| EvictAgent | [EvictAgentRequest](#spire.api.registration.EvictAgentRequest) | [EvictAgentResponse](#spire.api.registration.EvictAgentResponse) | EvictAgent removes an attestation entry from the attested nodes store |
| ListAgents | [ListAgentsRequest](#spire.api.registration.ListAgentsRequest) | [ListAgentsResponse](#spire.api.registration.ListAgentsResponse) | ListAgents will list all attested nodes |
| MintX509SVID | [MintX509SVIDRequest](#spire.api.registration.MintX509SVIDRequest) | [MintX509SVIDResponse](#spire.api.registration.MintX509SVIDResponse) | MintX509SVID mints an X509-SVID directly with the SPIRE server CA. |
| MintJWTSVID | [MintJWTSVIDRequest](#spire.api.registration.MintJWTSVIDRequest) | [MintJWTSVIDResponse](#spire.api.registration.MintJWTSVIDResponse) | MintJWTSVID mints a JWT-SVID directly with the SPIRE server CA. |
| GetNodeSelectors | [GetNodeSelectorsRequest](#spire.api.registration.GetNodeSelectorsRequest) | [GetNodeSelectorsResponse](#spire.api.registration.GetNodeSelectorsResponse) | GetNodeSelectors gets node (agent) selectors |

 



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

