# Protocol Documentation
<a name="top"/>

## Table of Contents

- [common.proto](#common.proto)
    - [AttestationData](#spire.common.AttestationData)
    - [Empty](#spire.common.Empty)
    - [RegistrationEntries](#spire.common.RegistrationEntries)
    - [RegistrationEntry](#spire.common.RegistrationEntry)
    - [Selector](#spire.common.Selector)
    - [Selectors](#spire.common.Selectors)
  
  
  
  

- [node.proto](#node.proto)
    - [AttestRequest](#spire.api.node.AttestRequest)
    - [AttestResponse](#spire.api.node.AttestResponse)
    - [FetchFederatedBundleRequest](#spire.api.node.FetchFederatedBundleRequest)
    - [FetchFederatedBundleResponse](#spire.api.node.FetchFederatedBundleResponse)
    - [FetchFederatedBundleResponse.FederatedBundlesEntry](#spire.api.node.FetchFederatedBundleResponse.FederatedBundlesEntry)
    - [FetchJWTSVIDRequest](#spire.api.node.FetchJWTSVIDRequest)
    - [FetchJWTSVIDResponse](#spire.api.node.FetchJWTSVIDResponse)
    - [FetchX509SVIDRequest](#spire.api.node.FetchX509SVIDRequest)
    - [FetchX509SVIDResponse](#spire.api.node.FetchX509SVIDResponse)
    - [JSR](#spire.api.node.JSR)
    - [JWTSVID](#spire.api.node.JWTSVID)
    - [X509SVID](#spire.api.node.X509SVID)
    - [X509SVIDUpdate](#spire.api.node.X509SVIDUpdate)
    - [X509SVIDUpdate.SvidsEntry](#spire.api.node.X509SVIDUpdate.SvidsEntry)
  
  
  
    - [Node](#spire.api.node.Node)
  

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
This is a curated record that the Server uses to set up and
manage the various registered nodes and workloads that are controlled by it.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectors | [Selector](#spire.common.Selector) | repeated | A list of selectors. |
| parent_id | [string](#string) |  | The SPIFFE ID of an entity that is authorized to attest the validity of a selector |
| spiffe_id | [string](#string) |  | The SPIFFE ID is a structured string used to identify a resource or caller. It is defined as a URI comprising a “trust domain” and an associated path. |
| ttl | [int32](#int32) |  | Time to live. |
| fb_spiffe_ids | [string](#string) | repeated | A list of federated bundle spiffe ids. |
| entry_id | [string](#string) |  | Entry ID |






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





 

 

 

 



<a name="node.proto"/>
<p align="right"><a href="#top">Top</a></p>

## node.proto



<a name="spire.api.node.AttestRequest"/>

### AttestRequest
Represents a request to attest the node.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestation_data | [.spire.common.AttestationData](#spire.api.node..spire.common.AttestationData) |  | A type which contains attestation data for specific platform. |
| csr | [bytes](#bytes) |  | Certificate signing request. |
| response | [bytes](#bytes) |  | Attestation challenge response |






<a name="spire.api.node.AttestResponse"/>

### AttestResponse
Represents a response that contains  map of signed SVIDs and an array of
all current Registration Entries which are relevant to the caller SPIFFE ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| svid_update | [X509SVIDUpdate](#spire.api.node.X509SVIDUpdate) |  | It includes a map of signed SVIDs and an array of all current Registration Entries which are relevant to the caller SPIFFE ID. |
| challenge | [bytes](#bytes) |  | This is a challenge issued by the server to the node. If populated, the node is expected to respond with another AttestRequest with the response. This field is mutually exclusive with the update field. |






<a name="spire.api.node.FetchFederatedBundleRequest"/>

### FetchFederatedBundleRequest
Represents a request with an array of SPIFFE Ids.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) | repeated | An array of SPIFFE Ids. |






<a name="spire.api.node.FetchFederatedBundleResponse"/>

### FetchFederatedBundleResponse
Represents a response with a map of SPIFFE Id, Federated CA Bundle.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federated_bundles | [FetchFederatedBundleResponse.FederatedBundlesEntry](#spire.api.node.FetchFederatedBundleResponse.FederatedBundlesEntry) | repeated | Map [ SPIFFE ID ] =&gt; Federated CA Bundle |






<a name="spire.api.node.FetchFederatedBundleResponse.FederatedBundlesEntry"/>

### FetchFederatedBundleResponse.FederatedBundlesEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [bytes](#bytes) |  |  |






<a name="spire.api.node.FetchJWTSVIDRequest"/>

### FetchJWTSVIDRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| jsr | [JSR](#spire.api.node.JSR) |  | The JWT signing request |






<a name="spire.api.node.FetchJWTSVIDResponse"/>

### FetchJWTSVIDResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| svid | [JWTSVID](#spire.api.node.JWTSVID) |  | The signed JWT-SVID |






<a name="spire.api.node.FetchX509SVIDRequest"/>

### FetchX509SVIDRequest
Represents a request with a list of CSR.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| csrs | [bytes](#bytes) | repeated | A list of CSRs |






<a name="spire.api.node.FetchX509SVIDResponse"/>

### FetchX509SVIDResponse
Represents a response that contains  map of signed SVIDs and an array
of all current Registration Entries which are relevant to the caller SPIFFE ID.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| svid_update | [X509SVIDUpdate](#spire.api.node.X509SVIDUpdate) |  | It includes a map of signed SVIDs and an array of all current Registration Entries which are relevant to the caller SPIFFE ID. |






<a name="spire.api.node.JSR"/>

### JSR
JSR is a JWT SVID signing request.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  | SPIFFE ID of the workload |
| audience | [string](#string) | repeated | List of intended audience |
| ttl | [int32](#int32) |  | Time-to-live in seconds. If unspecified the JWT SVID will be assigned a default time-to-live by the server. |






<a name="spire.api.node.JWTSVID"/>

### JWTSVID
JWTSVID is a signed JWT-SVID with fields lifted out for convenience.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| token | [string](#string) |  | JWT-SVID JWT token |
| expires_at | [int64](#int64) |  | SVID expiration timestamp (seconds since Unix epoch) |






<a name="spire.api.node.X509SVID"/>

### X509SVID
A type which contains the &#34;Spiffe Verifiable Identity Document&#34; and
a TTL indicating when the SVID expires.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cert | [bytes](#bytes) |  | X509 SVID (ASN.1 encoding) |
| expires_at | [int64](#int64) |  | SVID expiration timestamp (in seconds since Unix epoch) |






<a name="spire.api.node.X509SVIDUpdate"/>

### X509SVIDUpdate
A message returned by the Spire Server, which includes a map of signed SVIDs and
a list of all current Registration Entries which are relevant to the caller SPIFFE ID.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| svids | [X509SVIDUpdate.SvidsEntry](#spire.api.node.X509SVIDUpdate.SvidsEntry) | repeated | A map containing SVID values and corresponding SPIFFE IDs as the keys. Map[SPIFFE_ID] =&gt; SVID. |
| bundle | [bytes](#bytes) |  | Latest SPIRE Server bundle |
| registration_entries | [.spire.common.RegistrationEntry](#spire.api.node..spire.common.RegistrationEntry) | repeated | A type representing a curated record that the Spire Server uses to set up and manage the various registered nodes and workloads that are controlled by it. |






<a name="spire.api.node.X509SVIDUpdate.SvidsEntry"/>

### X509SVIDUpdate.SvidsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [X509SVID](#spire.api.node.X509SVID) |  |  |





 

 

 


<a name="spire.api.node.Node"/>

### Node


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Attest | [AttestRequest](#spire.api.node.AttestRequest) | [AttestResponse](#spire.api.node.AttestRequest) | Attest the node, get base node SVID. |
| FetchX509SVID | [FetchX509SVIDRequest](#spire.api.node.FetchX509SVIDRequest) | [FetchX509SVIDResponse](#spire.api.node.FetchX509SVIDRequest) | Get Workload, Node Agent certs and CA trust bundles. Also used for rotation Base Node SVID or the Registered Node SVID used for this call) List can be empty to allow Node Agent cache refresh). |
| FetchJWTSVID | [FetchJWTSVIDRequest](#spire.api.node.FetchJWTSVIDRequest) | [FetchJWTSVIDResponse](#spire.api.node.FetchJWTSVIDRequest) | Fetches a signed JWT-SVID for a workload intended for a specific audience. |
| FetchFederatedBundle | [FetchFederatedBundleRequest](#spire.api.node.FetchFederatedBundleRequest) | [FetchFederatedBundleResponse](#spire.api.node.FetchFederatedBundleRequest) | Called by the Node Agent to fetch the named Federated CA Bundle. Used in the event that authorized workloads reference a Federated Bundle. |

 



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

