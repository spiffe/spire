# Protocol Documentation
<a name="top"/>

## Table of Contents

- [plugin.proto](#plugin.proto)
    - [ConfigureRequest](#spire.common.plugin.ConfigureRequest)
    - [ConfigureRequest.GlobalConfig](#spire.common.plugin.ConfigureRequest.GlobalConfig)
    - [ConfigureResponse](#spire.common.plugin.ConfigureResponse)
    - [GetPluginInfoRequest](#spire.common.plugin.GetPluginInfoRequest)
    - [GetPluginInfoResponse](#spire.common.plugin.GetPluginInfoResponse)
  
  
  
  

- [common.proto](#common.proto)
    - [AttestationData](#spire.common.AttestationData)
    - [Bundle](#spire.common.Bundle)
    - [Certificate](#spire.common.Certificate)
    - [Empty](#spire.common.Empty)
    - [PublicKey](#spire.common.PublicKey)
    - [RegistrationEntries](#spire.common.RegistrationEntries)
    - [RegistrationEntry](#spire.common.RegistrationEntry)
    - [Selector](#spire.common.Selector)
    - [Selectors](#spire.common.Selectors)
  
  
  
  

- [noderesolver.proto](#noderesolver.proto)
    - [ResolveRequest](#spire.server.noderesolver.ResolveRequest)
    - [ResolveResponse](#spire.server.noderesolver.ResolveResponse)
    - [ResolveResponse.MapEntry](#spire.server.noderesolver.ResolveResponse.MapEntry)
  
  
  
    - [NodeResolver](#spire.server.noderesolver.NodeResolver)
  

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






<a name="spire.common.Bundle"/>

### Bundle



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| trust_domain_id | [string](#string) |  | the SPIFFE ID of the trust domain the bundle belongs to |
| root_cas | [Certificate](#spire.common.Certificate) | repeated | list of root CA certificates |
| jwt_signing_keys | [PublicKey](#spire.common.PublicKey) | repeated | list of JWT signing keys |






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





 

 

 

 



<a name="noderesolver.proto"/>
<p align="right"><a href="#top">Top</a></p>

## noderesolver.proto



<a name="spire.server.noderesolver.ResolveRequest"/>

### ResolveRequest
Represents a request with a list of BaseSPIFFEIDs.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| baseSpiffeIdList | [string](#string) | repeated | A list of BaseSPIFFE Ids. |






<a name="spire.server.noderesolver.ResolveResponse"/>

### ResolveResponse
Represents a response with a map of SPIFFE ID to a list of Selectors.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| map | [ResolveResponse.MapEntry](#spire.server.noderesolver.ResolveResponse.MapEntry) | repeated | Map[SPIFFE_ID] =&gt; Selectors. |






<a name="spire.server.noderesolver.ResolveResponse.MapEntry"/>

### ResolveResponse.MapEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [.spire.common.Selectors](#spire.server.noderesolver..spire.common.Selectors) |  |  |





 

 

 


<a name="spire.server.noderesolver.NodeResolver"/>

### NodeResolver


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Resolve | [ResolveRequest](#spire.server.noderesolver.ResolveRequest) | [ResolveResponse](#spire.server.noderesolver.ResolveRequest) | Retrieves a list of properties reflecting the current state of a particular node(s). |
| Configure | [spire.common.plugin.ConfigureRequest](#spire.common.plugin.ConfigureRequest) | [spire.common.plugin.ConfigureResponse](#spire.common.plugin.ConfigureRequest) | Responsible for configuration of the plugin. |
| GetPluginInfo | [spire.common.plugin.GetPluginInfoRequest](#spire.common.plugin.GetPluginInfoRequest) | [spire.common.plugin.GetPluginInfoResponse](#spire.common.plugin.GetPluginInfoRequest) | Returns the version and related metadata of the installed plugin. |

 



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

