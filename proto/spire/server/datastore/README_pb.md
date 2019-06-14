# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [datastore.proto](#datastore.proto)
    - [AppendBundleRequest](#spire.server.datastore.AppendBundleRequest)
    - [AppendBundleResponse](#spire.server.datastore.AppendBundleResponse)
    - [BySelectors](#spire.server.datastore.BySelectors)
    - [CreateAttestedNodeRequest](#spire.server.datastore.CreateAttestedNodeRequest)
    - [CreateAttestedNodeResponse](#spire.server.datastore.CreateAttestedNodeResponse)
    - [CreateBundleRequest](#spire.server.datastore.CreateBundleRequest)
    - [CreateBundleResponse](#spire.server.datastore.CreateBundleResponse)
    - [CreateJoinTokenRequest](#spire.server.datastore.CreateJoinTokenRequest)
    - [CreateJoinTokenResponse](#spire.server.datastore.CreateJoinTokenResponse)
    - [CreateRegistrationEntryRequest](#spire.server.datastore.CreateRegistrationEntryRequest)
    - [CreateRegistrationEntryResponse](#spire.server.datastore.CreateRegistrationEntryResponse)
    - [DeleteAttestedNodeRequest](#spire.server.datastore.DeleteAttestedNodeRequest)
    - [DeleteAttestedNodeResponse](#spire.server.datastore.DeleteAttestedNodeResponse)
    - [DeleteBundleRequest](#spire.server.datastore.DeleteBundleRequest)
    - [DeleteBundleResponse](#spire.server.datastore.DeleteBundleResponse)
    - [DeleteJoinTokenRequest](#spire.server.datastore.DeleteJoinTokenRequest)
    - [DeleteJoinTokenResponse](#spire.server.datastore.DeleteJoinTokenResponse)
    - [DeleteRegistrationEntryRequest](#spire.server.datastore.DeleteRegistrationEntryRequest)
    - [DeleteRegistrationEntryResponse](#spire.server.datastore.DeleteRegistrationEntryResponse)
    - [FetchAttestedNodeRequest](#spire.server.datastore.FetchAttestedNodeRequest)
    - [FetchAttestedNodeResponse](#spire.server.datastore.FetchAttestedNodeResponse)
    - [FetchBundleRequest](#spire.server.datastore.FetchBundleRequest)
    - [FetchBundleResponse](#spire.server.datastore.FetchBundleResponse)
    - [FetchJoinTokenRequest](#spire.server.datastore.FetchJoinTokenRequest)
    - [FetchJoinTokenResponse](#spire.server.datastore.FetchJoinTokenResponse)
    - [FetchRegistrationEntryRequest](#spire.server.datastore.FetchRegistrationEntryRequest)
    - [FetchRegistrationEntryResponse](#spire.server.datastore.FetchRegistrationEntryResponse)
    - [GetNodeSelectorsRequest](#spire.server.datastore.GetNodeSelectorsRequest)
    - [GetNodeSelectorsResponse](#spire.server.datastore.GetNodeSelectorsResponse)
    - [JoinToken](#spire.server.datastore.JoinToken)
    - [ListAttestedNodesRequest](#spire.server.datastore.ListAttestedNodesRequest)
    - [ListAttestedNodesResponse](#spire.server.datastore.ListAttestedNodesResponse)
    - [ListBundlesRequest](#spire.server.datastore.ListBundlesRequest)
    - [ListBundlesResponse](#spire.server.datastore.ListBundlesResponse)
    - [ListRegistrationEntriesRequest](#spire.server.datastore.ListRegistrationEntriesRequest)
    - [ListRegistrationEntriesResponse](#spire.server.datastore.ListRegistrationEntriesResponse)
    - [NodeSelectors](#spire.server.datastore.NodeSelectors)
    - [Pagination](#spire.server.datastore.Pagination)
    - [PruneBundleRequest](#spire.server.datastore.PruneBundleRequest)
    - [PruneBundleResponse](#spire.server.datastore.PruneBundleResponse)
    - [PruneJoinTokensRequest](#spire.server.datastore.PruneJoinTokensRequest)
    - [PruneJoinTokensResponse](#spire.server.datastore.PruneJoinTokensResponse)
    - [PruneRegistrationEntriesRequest](#spire.server.datastore.PruneRegistrationEntriesRequest)
    - [PruneRegistrationEntriesResponse](#spire.server.datastore.PruneRegistrationEntriesResponse)
    - [SetBundleRequest](#spire.server.datastore.SetBundleRequest)
    - [SetBundleResponse](#spire.server.datastore.SetBundleResponse)
    - [SetNodeSelectorsRequest](#spire.server.datastore.SetNodeSelectorsRequest)
    - [SetNodeSelectorsResponse](#spire.server.datastore.SetNodeSelectorsResponse)
    - [UpdateAttestedNodeRequest](#spire.server.datastore.UpdateAttestedNodeRequest)
    - [UpdateAttestedNodeResponse](#spire.server.datastore.UpdateAttestedNodeResponse)
    - [UpdateBundleRequest](#spire.server.datastore.UpdateBundleRequest)
    - [UpdateBundleResponse](#spire.server.datastore.UpdateBundleResponse)
    - [UpdateRegistrationEntryRequest](#spire.server.datastore.UpdateRegistrationEntryRequest)
    - [UpdateRegistrationEntryResponse](#spire.server.datastore.UpdateRegistrationEntryResponse)
  
    - [BySelectors.MatchBehavior](#spire.server.datastore.BySelectors.MatchBehavior)
    - [DeleteBundleRequest.Mode](#spire.server.datastore.DeleteBundleRequest.Mode)
  
  
    - [DataStore](#spire.server.datastore.DataStore)
  

- [Scalar Value Types](#scalar-value-types)



<a name="datastore.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## datastore.proto



<a name="spire.server.datastore.AppendBundleRequest"></a>

### AppendBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [spire.common.Bundle](#spire.common.Bundle) |  |  |






<a name="spire.server.datastore.AppendBundleResponse"></a>

### AppendBundleResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [spire.common.Bundle](#spire.common.Bundle) |  |  |






<a name="spire.server.datastore.BySelectors"></a>

### BySelectors



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectors | [spire.common.Selector](#spire.common.Selector) | repeated |  |
| match | [BySelectors.MatchBehavior](#spire.server.datastore.BySelectors.MatchBehavior) |  |  |






<a name="spire.server.datastore.CreateAttestedNodeRequest"></a>

### CreateAttestedNodeRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| node | [spire.common.AttestedNode](#spire.common.AttestedNode) |  |  |






<a name="spire.server.datastore.CreateAttestedNodeResponse"></a>

### CreateAttestedNodeResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| node | [spire.common.AttestedNode](#spire.common.AttestedNode) |  |  |






<a name="spire.server.datastore.CreateBundleRequest"></a>

### CreateBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [spire.common.Bundle](#spire.common.Bundle) |  |  |






<a name="spire.server.datastore.CreateBundleResponse"></a>

### CreateBundleResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [spire.common.Bundle](#spire.common.Bundle) |  |  |






<a name="spire.server.datastore.CreateJoinTokenRequest"></a>

### CreateJoinTokenRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| join_token | [JoinToken](#spire.server.datastore.JoinToken) |  |  |






<a name="spire.server.datastore.CreateJoinTokenResponse"></a>

### CreateJoinTokenResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| join_token | [JoinToken](#spire.server.datastore.JoinToken) |  |  |






<a name="spire.server.datastore.CreateRegistrationEntryRequest"></a>

### CreateRegistrationEntryRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry | [spire.common.RegistrationEntry](#spire.common.RegistrationEntry) |  |  |






<a name="spire.server.datastore.CreateRegistrationEntryResponse"></a>

### CreateRegistrationEntryResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry | [spire.common.RegistrationEntry](#spire.common.RegistrationEntry) |  |  |






<a name="spire.server.datastore.DeleteAttestedNodeRequest"></a>

### DeleteAttestedNodeRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  |  |






<a name="spire.server.datastore.DeleteAttestedNodeResponse"></a>

### DeleteAttestedNodeResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| node | [spire.common.AttestedNode](#spire.common.AttestedNode) |  |  |






<a name="spire.server.datastore.DeleteBundleRequest"></a>

### DeleteBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| trust_domain_id | [string](#string) |  |  |
| mode | [DeleteBundleRequest.Mode](#spire.server.datastore.DeleteBundleRequest.Mode) |  |  |






<a name="spire.server.datastore.DeleteBundleResponse"></a>

### DeleteBundleResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [spire.common.Bundle](#spire.common.Bundle) |  |  |






<a name="spire.server.datastore.DeleteJoinTokenRequest"></a>

### DeleteJoinTokenRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| token | [string](#string) |  |  |






<a name="spire.server.datastore.DeleteJoinTokenResponse"></a>

### DeleteJoinTokenResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| join_token | [JoinToken](#spire.server.datastore.JoinToken) |  |  |






<a name="spire.server.datastore.DeleteRegistrationEntryRequest"></a>

### DeleteRegistrationEntryRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry_id | [string](#string) |  |  |






<a name="spire.server.datastore.DeleteRegistrationEntryResponse"></a>

### DeleteRegistrationEntryResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry | [spire.common.RegistrationEntry](#spire.common.RegistrationEntry) |  |  |






<a name="spire.server.datastore.FetchAttestedNodeRequest"></a>

### FetchAttestedNodeRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  |  |






<a name="spire.server.datastore.FetchAttestedNodeResponse"></a>

### FetchAttestedNodeResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| node | [spire.common.AttestedNode](#spire.common.AttestedNode) |  |  |






<a name="spire.server.datastore.FetchBundleRequest"></a>

### FetchBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| trust_domain_id | [string](#string) |  |  |






<a name="spire.server.datastore.FetchBundleResponse"></a>

### FetchBundleResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [spire.common.Bundle](#spire.common.Bundle) |  |  |






<a name="spire.server.datastore.FetchJoinTokenRequest"></a>

### FetchJoinTokenRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| token | [string](#string) |  |  |






<a name="spire.server.datastore.FetchJoinTokenResponse"></a>

### FetchJoinTokenResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| join_token | [JoinToken](#spire.server.datastore.JoinToken) |  |  |






<a name="spire.server.datastore.FetchRegistrationEntryRequest"></a>

### FetchRegistrationEntryRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry_id | [string](#string) |  |  |






<a name="spire.server.datastore.FetchRegistrationEntryResponse"></a>

### FetchRegistrationEntryResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry | [spire.common.RegistrationEntry](#spire.common.RegistrationEntry) |  |  |






<a name="spire.server.datastore.GetNodeSelectorsRequest"></a>

### GetNodeSelectorsRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  |  |






<a name="spire.server.datastore.GetNodeSelectorsResponse"></a>

### GetNodeSelectorsResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectors | [NodeSelectors](#spire.server.datastore.NodeSelectors) |  |  |






<a name="spire.server.datastore.JoinToken"></a>

### JoinToken



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| token | [string](#string) |  | Token value |
| expiry | [int64](#int64) |  | Expiration in seconds since unix epoch |






<a name="spire.server.datastore.ListAttestedNodesRequest"></a>

### ListAttestedNodesRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| by_expires_before | [google.protobuf.Int64Value](#google.protobuf.Int64Value) |  |  |
| pagination | [Pagination](#spire.server.datastore.Pagination) |  |  |






<a name="spire.server.datastore.ListAttestedNodesResponse"></a>

### ListAttestedNodesResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodes | [spire.common.AttestedNode](#spire.common.AttestedNode) | repeated |  |
| pagination | [Pagination](#spire.server.datastore.Pagination) |  |  |






<a name="spire.server.datastore.ListBundlesRequest"></a>

### ListBundlesRequest







<a name="spire.server.datastore.ListBundlesResponse"></a>

### ListBundlesResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundles | [spire.common.Bundle](#spire.common.Bundle) | repeated |  |






<a name="spire.server.datastore.ListRegistrationEntriesRequest"></a>

### ListRegistrationEntriesRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| by_parent_id | [google.protobuf.StringValue](#google.protobuf.StringValue) |  |  |
| by_selectors | [BySelectors](#spire.server.datastore.BySelectors) |  |  |
| by_spiffe_id | [google.protobuf.StringValue](#google.protobuf.StringValue) |  |  |
| pagination | [Pagination](#spire.server.datastore.Pagination) |  |  |






<a name="spire.server.datastore.ListRegistrationEntriesResponse"></a>

### ListRegistrationEntriesResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entries | [spire.common.RegistrationEntry](#spire.common.RegistrationEntry) | repeated |  |
| pagination | [Pagination](#spire.server.datastore.Pagination) |  |  |






<a name="spire.server.datastore.NodeSelectors"></a>

### NodeSelectors



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  | Node SPIFFE ID |
| selectors | [spire.common.Selector](#spire.common.Selector) | repeated | Node selectors |






<a name="spire.server.datastore.Pagination"></a>

### Pagination



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| token | [string](#string) |  |  |
| page_size | [int32](#int32) |  |  |






<a name="spire.server.datastore.PruneBundleRequest"></a>

### PruneBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| trust_domain_id | [string](#string) |  | Trust domain of the bundle to prune |
| expires_before | [int64](#int64) |  | Expiration time |






<a name="spire.server.datastore.PruneBundleResponse"></a>

### PruneBundleResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle_changed | [bool](#bool) |  |  |






<a name="spire.server.datastore.PruneJoinTokensRequest"></a>

### PruneJoinTokensRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| expires_before | [int64](#int64) |  |  |






<a name="spire.server.datastore.PruneJoinTokensResponse"></a>

### PruneJoinTokensResponse







<a name="spire.server.datastore.PruneRegistrationEntriesRequest"></a>

### PruneRegistrationEntriesRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| expires_before | [int64](#int64) |  |  |






<a name="spire.server.datastore.PruneRegistrationEntriesResponse"></a>

### PruneRegistrationEntriesResponse







<a name="spire.server.datastore.SetBundleRequest"></a>

### SetBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [spire.common.Bundle](#spire.common.Bundle) |  |  |






<a name="spire.server.datastore.SetBundleResponse"></a>

### SetBundleResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [spire.common.Bundle](#spire.common.Bundle) |  |  |






<a name="spire.server.datastore.SetNodeSelectorsRequest"></a>

### SetNodeSelectorsRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectors | [NodeSelectors](#spire.server.datastore.NodeSelectors) |  |  |






<a name="spire.server.datastore.SetNodeSelectorsResponse"></a>

### SetNodeSelectorsResponse







<a name="spire.server.datastore.UpdateAttestedNodeRequest"></a>

### UpdateAttestedNodeRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  |  |
| cert_serial_number | [string](#string) |  |  |
| cert_not_after | [int64](#int64) |  |  |






<a name="spire.server.datastore.UpdateAttestedNodeResponse"></a>

### UpdateAttestedNodeResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| node | [spire.common.AttestedNode](#spire.common.AttestedNode) |  |  |






<a name="spire.server.datastore.UpdateBundleRequest"></a>

### UpdateBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [spire.common.Bundle](#spire.common.Bundle) |  |  |






<a name="spire.server.datastore.UpdateBundleResponse"></a>

### UpdateBundleResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [spire.common.Bundle](#spire.common.Bundle) |  |  |






<a name="spire.server.datastore.UpdateRegistrationEntryRequest"></a>

### UpdateRegistrationEntryRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry | [spire.common.RegistrationEntry](#spire.common.RegistrationEntry) |  |  |






<a name="spire.server.datastore.UpdateRegistrationEntryResponse"></a>

### UpdateRegistrationEntryResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry | [spire.common.RegistrationEntry](#spire.common.RegistrationEntry) |  |  |





 


<a name="spire.server.datastore.BySelectors.MatchBehavior"></a>

### BySelectors.MatchBehavior


| Name | Number | Description |
| ---- | ------ | ----------- |
| MATCH_EXACT | 0 |  |
| MATCH_SUBSET | 1 |  |



<a name="spire.server.datastore.DeleteBundleRequest.Mode"></a>

### DeleteBundleRequest.Mode
Mode controls the delete behavior if there are other records
associated with the bundle (e.g. registration entries).

| Name | Number | Description |
| ---- | ------ | ----------- |
| RESTRICT | 0 | RESTRICT prevents the bundle from being deleted in the presence of associated entries |
| DELETE | 1 | DELETE deletes the bundle and associated entries |
| DISSOCIATE | 2 | DISSOCIATE deletes the bundle and dissociates associated entries |


 

 


<a name="spire.server.datastore.DataStore"></a>

### DataStore


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| CreateBundle | [CreateBundleRequest](#spire.server.datastore.CreateBundleRequest) | [CreateBundleResponse](#spire.server.datastore.CreateBundleResponse) | Creates a bundle |
| FetchBundle | [FetchBundleRequest](#spire.server.datastore.FetchBundleRequest) | [FetchBundleResponse](#spire.server.datastore.FetchBundleResponse) | Fetches a specific bundle |
| ListBundles | [ListBundlesRequest](#spire.server.datastore.ListBundlesRequest) | [ListBundlesResponse](#spire.server.datastore.ListBundlesResponse) | Lists bundles (optionally filtered) |
| UpdateBundle | [UpdateBundleRequest](#spire.server.datastore.UpdateBundleRequest) | [UpdateBundleResponse](#spire.server.datastore.UpdateBundleResponse) | Updates a specific bundle |
| SetBundle | [SetBundleRequest](#spire.server.datastore.SetBundleRequest) | [SetBundleResponse](#spire.server.datastore.SetBundleResponse) | Sets bundle contents (creates if it does not exist) |
| AppendBundle | [AppendBundleRequest](#spire.server.datastore.AppendBundleRequest) | [AppendBundleResponse](#spire.server.datastore.AppendBundleResponse) | Appends contents from a specific bundle (creates if it does not exist) |
| DeleteBundle | [DeleteBundleRequest](#spire.server.datastore.DeleteBundleRequest) | [DeleteBundleResponse](#spire.server.datastore.DeleteBundleResponse) | Deletes a specific bundle |
| PruneBundle | [PruneBundleRequest](#spire.server.datastore.PruneBundleRequest) | [PruneBundleResponse](#spire.server.datastore.PruneBundleResponse) | Prunes all expired certificates and JWT signing keys from a bundle |
| CreateAttestedNode | [CreateAttestedNodeRequest](#spire.server.datastore.CreateAttestedNodeRequest) | [CreateAttestedNodeResponse](#spire.server.datastore.CreateAttestedNodeResponse) | Creates an attested node |
| FetchAttestedNode | [FetchAttestedNodeRequest](#spire.server.datastore.FetchAttestedNodeRequest) | [FetchAttestedNodeResponse](#spire.server.datastore.FetchAttestedNodeResponse) | Fetches a specific attested node |
| ListAttestedNodes | [ListAttestedNodesRequest](#spire.server.datastore.ListAttestedNodesRequest) | [ListAttestedNodesResponse](#spire.server.datastore.ListAttestedNodesResponse) | Lists attested nodes (optionally filtered) |
| UpdateAttestedNode | [UpdateAttestedNodeRequest](#spire.server.datastore.UpdateAttestedNodeRequest) | [UpdateAttestedNodeResponse](#spire.server.datastore.UpdateAttestedNodeResponse) | Updates a specific attested node |
| DeleteAttestedNode | [DeleteAttestedNodeRequest](#spire.server.datastore.DeleteAttestedNodeRequest) | [DeleteAttestedNodeResponse](#spire.server.datastore.DeleteAttestedNodeResponse) | Deletes a specific attested node |
| SetNodeSelectors | [SetNodeSelectorsRequest](#spire.server.datastore.SetNodeSelectorsRequest) | [SetNodeSelectorsResponse](#spire.server.datastore.SetNodeSelectorsResponse) | Sets the set of selectors for a specific node id |
| GetNodeSelectors | [GetNodeSelectorsRequest](#spire.server.datastore.GetNodeSelectorsRequest) | [GetNodeSelectorsResponse](#spire.server.datastore.GetNodeSelectorsResponse) | Gets the set of node selectors for a specific node id |
| CreateRegistrationEntry | [CreateRegistrationEntryRequest](#spire.server.datastore.CreateRegistrationEntryRequest) | [CreateRegistrationEntryResponse](#spire.server.datastore.CreateRegistrationEntryResponse) | Creates a registration entry |
| FetchRegistrationEntry | [FetchRegistrationEntryRequest](#spire.server.datastore.FetchRegistrationEntryRequest) | [FetchRegistrationEntryResponse](#spire.server.datastore.FetchRegistrationEntryResponse) | Fetches a specific registration entry |
| ListRegistrationEntries | [ListRegistrationEntriesRequest](#spire.server.datastore.ListRegistrationEntriesRequest) | [ListRegistrationEntriesResponse](#spire.server.datastore.ListRegistrationEntriesResponse) | Lists registration entries (optionally filtered) |
| UpdateRegistrationEntry | [UpdateRegistrationEntryRequest](#spire.server.datastore.UpdateRegistrationEntryRequest) | [UpdateRegistrationEntryResponse](#spire.server.datastore.UpdateRegistrationEntryResponse) | Updates a specific registration entry |
| DeleteRegistrationEntry | [DeleteRegistrationEntryRequest](#spire.server.datastore.DeleteRegistrationEntryRequest) | [DeleteRegistrationEntryResponse](#spire.server.datastore.DeleteRegistrationEntryResponse) | Deletes a specific registration entry |
| PruneRegistrationEntries | [PruneRegistrationEntriesRequest](#spire.server.datastore.PruneRegistrationEntriesRequest) | [PruneRegistrationEntriesResponse](#spire.server.datastore.PruneRegistrationEntriesResponse) | Prunes all registration entries that expire before the specified timestamp |
| CreateJoinToken | [CreateJoinTokenRequest](#spire.server.datastore.CreateJoinTokenRequest) | [CreateJoinTokenResponse](#spire.server.datastore.CreateJoinTokenResponse) | Creates a join token |
| FetchJoinToken | [FetchJoinTokenRequest](#spire.server.datastore.FetchJoinTokenRequest) | [FetchJoinTokenResponse](#spire.server.datastore.FetchJoinTokenResponse) | Fetches a specific join token |
| DeleteJoinToken | [DeleteJoinTokenRequest](#spire.server.datastore.DeleteJoinTokenRequest) | [DeleteJoinTokenResponse](#spire.server.datastore.DeleteJoinTokenResponse) | Delete a specific join token |
| PruneJoinTokens | [PruneJoinTokensRequest](#spire.server.datastore.PruneJoinTokensRequest) | [PruneJoinTokensResponse](#spire.server.datastore.PruneJoinTokensResponse) | Prunes all join tokens that expire before the specified timestamp |
| Configure | [.spire.common.plugin.ConfigureRequest](#spire.common.plugin.ConfigureRequest) | [.spire.common.plugin.ConfigureResponse](#spire.common.plugin.ConfigureResponse) | Applies the plugin configuration |
| GetPluginInfo | [.spire.common.plugin.GetPluginInfoRequest](#spire.common.plugin.GetPluginInfoRequest) | [.spire.common.plugin.GetPluginInfoResponse](#spire.common.plugin.GetPluginInfoResponse) | Returns the version and related metadata of the installed plugin |

 



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

