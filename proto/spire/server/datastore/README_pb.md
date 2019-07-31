# Protocol Documentation
<a name="top"/>

## Table of Contents

- [wrappers.proto](#wrappers.proto)
    - [BoolValue](#google.protobuf.BoolValue)
    - [BytesValue](#google.protobuf.BytesValue)
    - [DoubleValue](#google.protobuf.DoubleValue)
    - [FloatValue](#google.protobuf.FloatValue)
    - [Int32Value](#google.protobuf.Int32Value)
    - [Int64Value](#google.protobuf.Int64Value)
    - [StringValue](#google.protobuf.StringValue)
    - [UInt32Value](#google.protobuf.UInt32Value)
    - [UInt64Value](#google.protobuf.UInt64Value)
  
  
  
  

- [plugin.proto](#plugin.proto)
    - [ConfigureRequest](#spire.common.plugin.ConfigureRequest)
    - [ConfigureRequest.GlobalConfig](#spire.common.plugin.ConfigureRequest.GlobalConfig)
    - [ConfigureResponse](#spire.common.plugin.ConfigureResponse)
    - [GetPluginInfoRequest](#spire.common.plugin.GetPluginInfoRequest)
    - [GetPluginInfoResponse](#spire.common.plugin.GetPluginInfoResponse)
    - [InitRequest](#spire.common.plugin.InitRequest)
    - [InitResponse](#spire.common.plugin.InitResponse)
  
  
  
    - [PluginInit](#spire.common.plugin.PluginInit)
  

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



<a name="wrappers.proto"/>
<p align="right"><a href="#top">Top</a></p>

## wrappers.proto



<a name="google.protobuf.BoolValue"/>

### BoolValue
Wrapper message for `bool`.

The JSON representation for `BoolValue` is JSON `true` and `false`.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| value | [bool](#bool) |  | The bool value. |






<a name="google.protobuf.BytesValue"/>

### BytesValue
Wrapper message for `bytes`.

The JSON representation for `BytesValue` is JSON string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| value | [bytes](#bytes) |  | The bytes value. |






<a name="google.protobuf.DoubleValue"/>

### DoubleValue
Wrapper message for `double`.

The JSON representation for `DoubleValue` is JSON number.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| value | [double](#double) |  | The double value. |






<a name="google.protobuf.FloatValue"/>

### FloatValue
Wrapper message for `float`.

The JSON representation for `FloatValue` is JSON number.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| value | [float](#float) |  | The float value. |






<a name="google.protobuf.Int32Value"/>

### Int32Value
Wrapper message for `int32`.

The JSON representation for `Int32Value` is JSON number.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| value | [int32](#int32) |  | The int32 value. |






<a name="google.protobuf.Int64Value"/>

### Int64Value
Wrapper message for `int64`.

The JSON representation for `Int64Value` is JSON string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| value | [int64](#int64) |  | The int64 value. |






<a name="google.protobuf.StringValue"/>

### StringValue
Wrapper message for `string`.

The JSON representation for `StringValue` is JSON string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| value | [string](#string) |  | The string value. |






<a name="google.protobuf.UInt32Value"/>

### UInt32Value
Wrapper message for `uint32`.

The JSON representation for `UInt32Value` is JSON number.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| value | [uint32](#uint32) |  | The uint32 value. |






<a name="google.protobuf.UInt64Value"/>

### UInt64Value
Wrapper message for `uint64`.

The JSON representation for `UInt64Value` is JSON string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| value | [uint64](#uint64) |  | The uint64 value. |





 

 

 

 



<a name="plugin.proto"/>
<p align="right"><a href="#top">Top</a></p>

## plugin.proto



<a name="spire.common.plugin.ConfigureRequest"/>

### ConfigureRequest
Represents the plugin-specific configuration string.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| configuration | [string](#string) |  | The configuration for the plugin. |
| globalConfig | [ConfigureRequest.GlobalConfig](#spire.common.plugin.ConfigureRequest.GlobalConfig) |  | Global configurations. |






<a name="spire.common.plugin.ConfigureRequest.GlobalConfig"/>

### ConfigureRequest.GlobalConfig
Global configuration nested type.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| trustDomain | [string](#string) |  |  |






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






<a name="spire.common.plugin.InitRequest"/>

### InitRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| host_services | [string](#string) | repeated |  |






<a name="spire.common.plugin.InitResponse"/>

### InitResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| plugin_services | [string](#string) | repeated |  |





 

 

 


<a name="spire.common.plugin.PluginInit"/>

### PluginInit


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Init | [InitRequest](#spire.common.plugin.InitRequest) | [InitResponse](#spire.common.plugin.InitRequest) |  |

 



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
| registrant | [string](#string) |  | SPIFFE ID of the workload that created this registration entry |






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





 

 

 

 



<a name="datastore.proto"/>
<p align="right"><a href="#top">Top</a></p>

## datastore.proto



<a name="spire.server.datastore.AppendBundleRequest"/>

### AppendBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [.spire.common.Bundle](#spire.server.datastore..spire.common.Bundle) |  |  |






<a name="spire.server.datastore.AppendBundleResponse"/>

### AppendBundleResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [.spire.common.Bundle](#spire.server.datastore..spire.common.Bundle) |  |  |






<a name="spire.server.datastore.BySelectors"/>

### BySelectors



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectors | [.spire.common.Selector](#spire.server.datastore..spire.common.Selector) | repeated |  |
| match | [BySelectors.MatchBehavior](#spire.server.datastore.BySelectors.MatchBehavior) |  |  |






<a name="spire.server.datastore.CreateAttestedNodeRequest"/>

### CreateAttestedNodeRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| node | [.spire.common.AttestedNode](#spire.server.datastore..spire.common.AttestedNode) |  |  |






<a name="spire.server.datastore.CreateAttestedNodeResponse"/>

### CreateAttestedNodeResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| node | [.spire.common.AttestedNode](#spire.server.datastore..spire.common.AttestedNode) |  |  |






<a name="spire.server.datastore.CreateBundleRequest"/>

### CreateBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [.spire.common.Bundle](#spire.server.datastore..spire.common.Bundle) |  |  |






<a name="spire.server.datastore.CreateBundleResponse"/>

### CreateBundleResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [.spire.common.Bundle](#spire.server.datastore..spire.common.Bundle) |  |  |






<a name="spire.server.datastore.CreateJoinTokenRequest"/>

### CreateJoinTokenRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| join_token | [JoinToken](#spire.server.datastore.JoinToken) |  |  |






<a name="spire.server.datastore.CreateJoinTokenResponse"/>

### CreateJoinTokenResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| join_token | [JoinToken](#spire.server.datastore.JoinToken) |  |  |






<a name="spire.server.datastore.CreateRegistrationEntryRequest"/>

### CreateRegistrationEntryRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry | [.spire.common.RegistrationEntry](#spire.server.datastore..spire.common.RegistrationEntry) |  |  |






<a name="spire.server.datastore.CreateRegistrationEntryResponse"/>

### CreateRegistrationEntryResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry | [.spire.common.RegistrationEntry](#spire.server.datastore..spire.common.RegistrationEntry) |  |  |






<a name="spire.server.datastore.DeleteAttestedNodeRequest"/>

### DeleteAttestedNodeRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  |  |






<a name="spire.server.datastore.DeleteAttestedNodeResponse"/>

### DeleteAttestedNodeResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| node | [.spire.common.AttestedNode](#spire.server.datastore..spire.common.AttestedNode) |  |  |






<a name="spire.server.datastore.DeleteBundleRequest"/>

### DeleteBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| trust_domain_id | [string](#string) |  |  |
| mode | [DeleteBundleRequest.Mode](#spire.server.datastore.DeleteBundleRequest.Mode) |  |  |






<a name="spire.server.datastore.DeleteBundleResponse"/>

### DeleteBundleResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [.spire.common.Bundle](#spire.server.datastore..spire.common.Bundle) |  |  |






<a name="spire.server.datastore.DeleteJoinTokenRequest"/>

### DeleteJoinTokenRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| token | [string](#string) |  |  |






<a name="spire.server.datastore.DeleteJoinTokenResponse"/>

### DeleteJoinTokenResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| join_token | [JoinToken](#spire.server.datastore.JoinToken) |  |  |






<a name="spire.server.datastore.DeleteRegistrationEntryRequest"/>

### DeleteRegistrationEntryRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry_id | [string](#string) |  |  |






<a name="spire.server.datastore.DeleteRegistrationEntryResponse"/>

### DeleteRegistrationEntryResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry | [.spire.common.RegistrationEntry](#spire.server.datastore..spire.common.RegistrationEntry) |  |  |






<a name="spire.server.datastore.FetchAttestedNodeRequest"/>

### FetchAttestedNodeRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  |  |






<a name="spire.server.datastore.FetchAttestedNodeResponse"/>

### FetchAttestedNodeResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| node | [.spire.common.AttestedNode](#spire.server.datastore..spire.common.AttestedNode) |  |  |






<a name="spire.server.datastore.FetchBundleRequest"/>

### FetchBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| trust_domain_id | [string](#string) |  |  |






<a name="spire.server.datastore.FetchBundleResponse"/>

### FetchBundleResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [.spire.common.Bundle](#spire.server.datastore..spire.common.Bundle) |  |  |






<a name="spire.server.datastore.FetchJoinTokenRequest"/>

### FetchJoinTokenRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| token | [string](#string) |  |  |






<a name="spire.server.datastore.FetchJoinTokenResponse"/>

### FetchJoinTokenResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| join_token | [JoinToken](#spire.server.datastore.JoinToken) |  |  |






<a name="spire.server.datastore.FetchRegistrationEntryRequest"/>

### FetchRegistrationEntryRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry_id | [string](#string) |  |  |






<a name="spire.server.datastore.FetchRegistrationEntryResponse"/>

### FetchRegistrationEntryResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry | [.spire.common.RegistrationEntry](#spire.server.datastore..spire.common.RegistrationEntry) |  |  |






<a name="spire.server.datastore.GetNodeSelectorsRequest"/>

### GetNodeSelectorsRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  |  |






<a name="spire.server.datastore.GetNodeSelectorsResponse"/>

### GetNodeSelectorsResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectors | [NodeSelectors](#spire.server.datastore.NodeSelectors) |  |  |






<a name="spire.server.datastore.JoinToken"/>

### JoinToken



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| token | [string](#string) |  | Token value |
| expiry | [int64](#int64) |  | Expiration in seconds since unix epoch |






<a name="spire.server.datastore.ListAttestedNodesRequest"/>

### ListAttestedNodesRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| by_expires_before | [.google.protobuf.Int64Value](#spire.server.datastore..google.protobuf.Int64Value) |  |  |
| pagination | [Pagination](#spire.server.datastore.Pagination) |  |  |






<a name="spire.server.datastore.ListAttestedNodesResponse"/>

### ListAttestedNodesResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodes | [.spire.common.AttestedNode](#spire.server.datastore..spire.common.AttestedNode) | repeated |  |
| pagination | [Pagination](#spire.server.datastore.Pagination) |  |  |






<a name="spire.server.datastore.ListBundlesRequest"/>

### ListBundlesRequest







<a name="spire.server.datastore.ListBundlesResponse"/>

### ListBundlesResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundles | [.spire.common.Bundle](#spire.server.datastore..spire.common.Bundle) | repeated |  |






<a name="spire.server.datastore.ListRegistrationEntriesRequest"/>

### ListRegistrationEntriesRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| by_parent_id | [.google.protobuf.StringValue](#spire.server.datastore..google.protobuf.StringValue) |  |  |
| by_selectors | [BySelectors](#spire.server.datastore.BySelectors) |  |  |
| by_spiffe_id | [.google.protobuf.StringValue](#spire.server.datastore..google.protobuf.StringValue) |  |  |
| pagination | [Pagination](#spire.server.datastore.Pagination) |  |  |
| by_registrant_id | [.google.protobuf.StringValue](#spire.server.datastore..google.protobuf.StringValue) |  |  |






<a name="spire.server.datastore.ListRegistrationEntriesResponse"/>

### ListRegistrationEntriesResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entries | [.spire.common.RegistrationEntry](#spire.server.datastore..spire.common.RegistrationEntry) | repeated |  |
| pagination | [Pagination](#spire.server.datastore.Pagination) |  |  |






<a name="spire.server.datastore.NodeSelectors"/>

### NodeSelectors



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  | Node SPIFFE ID |
| selectors | [.spire.common.Selector](#spire.server.datastore..spire.common.Selector) | repeated | Node selectors |






<a name="spire.server.datastore.Pagination"/>

### Pagination



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| token | [string](#string) |  |  |
| page_size | [int32](#int32) |  |  |






<a name="spire.server.datastore.PruneBundleRequest"/>

### PruneBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| trust_domain_id | [string](#string) |  | Trust domain of the bundle to prune |
| expires_before | [int64](#int64) |  | Expiration time |






<a name="spire.server.datastore.PruneBundleResponse"/>

### PruneBundleResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle_changed | [bool](#bool) |  |  |






<a name="spire.server.datastore.PruneJoinTokensRequest"/>

### PruneJoinTokensRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| expires_before | [int64](#int64) |  |  |






<a name="spire.server.datastore.PruneJoinTokensResponse"/>

### PruneJoinTokensResponse







<a name="spire.server.datastore.PruneRegistrationEntriesRequest"/>

### PruneRegistrationEntriesRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| expires_before | [int64](#int64) |  |  |






<a name="spire.server.datastore.PruneRegistrationEntriesResponse"/>

### PruneRegistrationEntriesResponse







<a name="spire.server.datastore.SetBundleRequest"/>

### SetBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [.spire.common.Bundle](#spire.server.datastore..spire.common.Bundle) |  |  |






<a name="spire.server.datastore.SetBundleResponse"/>

### SetBundleResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [.spire.common.Bundle](#spire.server.datastore..spire.common.Bundle) |  |  |






<a name="spire.server.datastore.SetNodeSelectorsRequest"/>

### SetNodeSelectorsRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectors | [NodeSelectors](#spire.server.datastore.NodeSelectors) |  |  |






<a name="spire.server.datastore.SetNodeSelectorsResponse"/>

### SetNodeSelectorsResponse







<a name="spire.server.datastore.UpdateAttestedNodeRequest"/>

### UpdateAttestedNodeRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  |  |
| cert_serial_number | [string](#string) |  |  |
| cert_not_after | [int64](#int64) |  |  |






<a name="spire.server.datastore.UpdateAttestedNodeResponse"/>

### UpdateAttestedNodeResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| node | [.spire.common.AttestedNode](#spire.server.datastore..spire.common.AttestedNode) |  |  |






<a name="spire.server.datastore.UpdateBundleRequest"/>

### UpdateBundleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [.spire.common.Bundle](#spire.server.datastore..spire.common.Bundle) |  |  |






<a name="spire.server.datastore.UpdateBundleResponse"/>

### UpdateBundleResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [.spire.common.Bundle](#spire.server.datastore..spire.common.Bundle) |  |  |






<a name="spire.server.datastore.UpdateRegistrationEntryRequest"/>

### UpdateRegistrationEntryRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry | [.spire.common.RegistrationEntry](#spire.server.datastore..spire.common.RegistrationEntry) |  |  |






<a name="spire.server.datastore.UpdateRegistrationEntryResponse"/>

### UpdateRegistrationEntryResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry | [.spire.common.RegistrationEntry](#spire.server.datastore..spire.common.RegistrationEntry) |  |  |





 


<a name="spire.server.datastore.BySelectors.MatchBehavior"/>

### BySelectors.MatchBehavior


| Name | Number | Description |
| ---- | ------ | ----------- |
| MATCH_EXACT | 0 |  |
| MATCH_SUBSET | 1 |  |



<a name="spire.server.datastore.DeleteBundleRequest.Mode"/>

### DeleteBundleRequest.Mode
Mode controls the delete behavior if there are other records
associated with the bundle (e.g. registration entries).

| Name | Number | Description |
| ---- | ------ | ----------- |
| RESTRICT | 0 | RESTRICT prevents the bundle from being deleted in the presence of associated entries |
| DELETE | 1 | DELETE deletes the bundle and associated entries |
| DISSOCIATE | 2 | DISSOCIATE deletes the bundle and dissociates associated entries |


 

 


<a name="spire.server.datastore.DataStore"/>

### DataStore


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| CreateBundle | [CreateBundleRequest](#spire.server.datastore.CreateBundleRequest) | [CreateBundleResponse](#spire.server.datastore.CreateBundleRequest) | Creates a bundle |
| FetchBundle | [FetchBundleRequest](#spire.server.datastore.FetchBundleRequest) | [FetchBundleResponse](#spire.server.datastore.FetchBundleRequest) | Fetches a specific bundle |
| ListBundles | [ListBundlesRequest](#spire.server.datastore.ListBundlesRequest) | [ListBundlesResponse](#spire.server.datastore.ListBundlesRequest) | Lists bundles (optionally filtered) |
| UpdateBundle | [UpdateBundleRequest](#spire.server.datastore.UpdateBundleRequest) | [UpdateBundleResponse](#spire.server.datastore.UpdateBundleRequest) | Updates a specific bundle |
| SetBundle | [SetBundleRequest](#spire.server.datastore.SetBundleRequest) | [SetBundleResponse](#spire.server.datastore.SetBundleRequest) | Sets bundle contents (creates if it does not exist) |
| AppendBundle | [AppendBundleRequest](#spire.server.datastore.AppendBundleRequest) | [AppendBundleResponse](#spire.server.datastore.AppendBundleRequest) | Appends contents from a specific bundle (creates if it does not exist) |
| DeleteBundle | [DeleteBundleRequest](#spire.server.datastore.DeleteBundleRequest) | [DeleteBundleResponse](#spire.server.datastore.DeleteBundleRequest) | Deletes a specific bundle |
| PruneBundle | [PruneBundleRequest](#spire.server.datastore.PruneBundleRequest) | [PruneBundleResponse](#spire.server.datastore.PruneBundleRequest) | Prunes all expired certificates and JWT signing keys from a bundle |
| CreateAttestedNode | [CreateAttestedNodeRequest](#spire.server.datastore.CreateAttestedNodeRequest) | [CreateAttestedNodeResponse](#spire.server.datastore.CreateAttestedNodeRequest) | Creates an attested node |
| FetchAttestedNode | [FetchAttestedNodeRequest](#spire.server.datastore.FetchAttestedNodeRequest) | [FetchAttestedNodeResponse](#spire.server.datastore.FetchAttestedNodeRequest) | Fetches a specific attested node |
| ListAttestedNodes | [ListAttestedNodesRequest](#spire.server.datastore.ListAttestedNodesRequest) | [ListAttestedNodesResponse](#spire.server.datastore.ListAttestedNodesRequest) | Lists attested nodes (optionally filtered) |
| UpdateAttestedNode | [UpdateAttestedNodeRequest](#spire.server.datastore.UpdateAttestedNodeRequest) | [UpdateAttestedNodeResponse](#spire.server.datastore.UpdateAttestedNodeRequest) | Updates a specific attested node |
| DeleteAttestedNode | [DeleteAttestedNodeRequest](#spire.server.datastore.DeleteAttestedNodeRequest) | [DeleteAttestedNodeResponse](#spire.server.datastore.DeleteAttestedNodeRequest) | Deletes a specific attested node |
| SetNodeSelectors | [SetNodeSelectorsRequest](#spire.server.datastore.SetNodeSelectorsRequest) | [SetNodeSelectorsResponse](#spire.server.datastore.SetNodeSelectorsRequest) | Sets the set of selectors for a specific node id |
| GetNodeSelectors | [GetNodeSelectorsRequest](#spire.server.datastore.GetNodeSelectorsRequest) | [GetNodeSelectorsResponse](#spire.server.datastore.GetNodeSelectorsRequest) | Gets the set of node selectors for a specific node id |
| CreateRegistrationEntry | [CreateRegistrationEntryRequest](#spire.server.datastore.CreateRegistrationEntryRequest) | [CreateRegistrationEntryResponse](#spire.server.datastore.CreateRegistrationEntryRequest) | Creates a registration entry |
| FetchRegistrationEntry | [FetchRegistrationEntryRequest](#spire.server.datastore.FetchRegistrationEntryRequest) | [FetchRegistrationEntryResponse](#spire.server.datastore.FetchRegistrationEntryRequest) | Fetches a specific registration entry |
| ListRegistrationEntries | [ListRegistrationEntriesRequest](#spire.server.datastore.ListRegistrationEntriesRequest) | [ListRegistrationEntriesResponse](#spire.server.datastore.ListRegistrationEntriesRequest) | Lists registration entries (optionally filtered) |
| UpdateRegistrationEntry | [UpdateRegistrationEntryRequest](#spire.server.datastore.UpdateRegistrationEntryRequest) | [UpdateRegistrationEntryResponse](#spire.server.datastore.UpdateRegistrationEntryRequest) | Updates a specific registration entry |
| DeleteRegistrationEntry | [DeleteRegistrationEntryRequest](#spire.server.datastore.DeleteRegistrationEntryRequest) | [DeleteRegistrationEntryResponse](#spire.server.datastore.DeleteRegistrationEntryRequest) | Deletes a specific registration entry |
| PruneRegistrationEntries | [PruneRegistrationEntriesRequest](#spire.server.datastore.PruneRegistrationEntriesRequest) | [PruneRegistrationEntriesResponse](#spire.server.datastore.PruneRegistrationEntriesRequest) | Prunes all registration entries that expire before the specified timestamp |
| CreateJoinToken | [CreateJoinTokenRequest](#spire.server.datastore.CreateJoinTokenRequest) | [CreateJoinTokenResponse](#spire.server.datastore.CreateJoinTokenRequest) | Creates a join token |
| FetchJoinToken | [FetchJoinTokenRequest](#spire.server.datastore.FetchJoinTokenRequest) | [FetchJoinTokenResponse](#spire.server.datastore.FetchJoinTokenRequest) | Fetches a specific join token |
| DeleteJoinToken | [DeleteJoinTokenRequest](#spire.server.datastore.DeleteJoinTokenRequest) | [DeleteJoinTokenResponse](#spire.server.datastore.DeleteJoinTokenRequest) | Delete a specific join token |
| PruneJoinTokens | [PruneJoinTokensRequest](#spire.server.datastore.PruneJoinTokensRequest) | [PruneJoinTokensResponse](#spire.server.datastore.PruneJoinTokensRequest) | Prunes all join tokens that expire before the specified timestamp |
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

