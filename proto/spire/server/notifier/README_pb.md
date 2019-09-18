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
  
  
  
  

- [plugin.proto](#plugin.proto)
    - [ConfigureRequest](#spire.common.plugin.ConfigureRequest)
    - [ConfigureRequest.GlobalConfig](#spire.common.plugin.ConfigureRequest.GlobalConfig)
    - [ConfigureResponse](#spire.common.plugin.ConfigureResponse)
    - [GetPluginInfoRequest](#spire.common.plugin.GetPluginInfoRequest)
    - [GetPluginInfoResponse](#spire.common.plugin.GetPluginInfoResponse)
    - [InitRequest](#spire.common.plugin.InitRequest)
    - [InitResponse](#spire.common.plugin.InitResponse)
  
  
  
    - [PluginInit](#spire.common.plugin.PluginInit)
  

- [notifier.proto](#notifier.proto)
    - [BundleLoaded](#spire.server.notifier.BundleLoaded)
    - [BundleUpdated](#spire.server.notifier.BundleUpdated)
    - [NotifyAndAdviseRequest](#spire.server.notifier.NotifyAndAdviseRequest)
    - [NotifyAndAdviseResponse](#spire.server.notifier.NotifyAndAdviseResponse)
    - [NotifyRequest](#spire.server.notifier.NotifyRequest)
    - [NotifyResponse](#spire.server.notifier.NotifyResponse)
  
  
  
    - [Notifier](#spire.server.notifier.Notifier)
  

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
| prepared_cert_serial_number | [string](#string) |  | Node certificate serial number |
| prepared_cert_not_after | [int64](#int64) |  | Node certificate not_after (seconds since unix epoch) |






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

 



<a name="notifier.proto"/>
<p align="right"><a href="#top">Top</a></p>

## notifier.proto



<a name="spire.server.notifier.BundleLoaded"/>

### BundleLoaded



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [.spire.common.Bundle](#spire.server.notifier..spire.common.Bundle) |  |  |






<a name="spire.server.notifier.BundleUpdated"/>

### BundleUpdated



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [.spire.common.Bundle](#spire.server.notifier..spire.common.Bundle) |  |  |






<a name="spire.server.notifier.NotifyAndAdviseRequest"/>

### NotifyAndAdviseRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle_loaded | [BundleLoaded](#spire.server.notifier.BundleLoaded) |  | BundleLoaded is emitted on startup after SPIRE server creates/loads the trust bundle. If an error is returned SPIRE server is shut down. |






<a name="spire.server.notifier.NotifyAndAdviseResponse"/>

### NotifyAndAdviseResponse







<a name="spire.server.notifier.NotifyRequest"/>

### NotifyRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle_updated | [BundleUpdated](#spire.server.notifier.BundleUpdated) |  | BundleUpdated is emitted whenever SPIRE server changes the trust bundle. |






<a name="spire.server.notifier.NotifyResponse"/>

### NotifyResponse






 

 

 


<a name="spire.server.notifier.Notifier"/>

### Notifier


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Notify | [NotifyRequest](#spire.server.notifier.NotifyRequest) | [NotifyResponse](#spire.server.notifier.NotifyRequest) | Notify notifies the plugin that an event occurred. Errors returned by the plugin are logged but otherwise ignored. |
| NotifyAndAdvise | [NotifyAndAdviseRequest](#spire.server.notifier.NotifyAndAdviseRequest) | [NotifyAndAdviseResponse](#spire.server.notifier.NotifyAndAdviseRequest) | NotifyAndAdvise notifies the plugin that an event occurred and waits for a response. Errors returned by the plugin control SPIRE server behavior. See NotifyAndAdviseRequest for per-event details. |
| Configure | [spire.common.plugin.ConfigureRequest](#spire.common.plugin.ConfigureRequest) | [spire.common.plugin.ConfigureResponse](#spire.common.plugin.ConfigureRequest) |  |
| GetPluginInfo | [spire.common.plugin.GetPluginInfoRequest](#spire.common.plugin.GetPluginInfoRequest) | [spire.common.plugin.GetPluginInfoResponse](#spire.common.plugin.GetPluginInfoRequest) |  |

 



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

