# Protocol Documentation
<a name="top"/>

## Table of Contents


* [common.proto](#common.proto)
  
    * [AttestedData](#common.AttestedData)
  
    * [Empty](#common.Empty)
  
    * [RegistrationEntries](#common.RegistrationEntries)
  
    * [RegistrationEntry](#common.RegistrationEntry)
  
    * [Selector](#common.Selector)
  
    * [Selectors](#common.Selectors)
  
  
  
  


* [node.proto](#node.proto)
  
    * [FetchBaseSVIDRequest](#node.FetchBaseSVIDRequest)
  
    * [FetchBaseSVIDResponse](#node.FetchBaseSVIDResponse)
  
    * [FetchCPBundleRequest](#node.FetchCPBundleRequest)
  
    * [FetchCPBundleResponse](#node.FetchCPBundleResponse)
  
    * [FetchFederatedBundleRequest](#node.FetchFederatedBundleRequest)
  
    * [FetchFederatedBundleResponse](#node.FetchFederatedBundleResponse)
  
    * [FetchFederatedBundleResponse.FederatedBundlesEntry](#node.FetchFederatedBundleResponse.FederatedBundlesEntry)
  
    * [FetchSVIDRequest](#node.FetchSVIDRequest)
  
    * [FetchSVIDResponse](#node.FetchSVIDResponse)
  
    * [Svid](#node.Svid)
  
    * [SvidUpdate](#node.SvidUpdate)
  
    * [SvidUpdate.SvidsEntry](#node.SvidUpdate.SvidsEntry)
  
  
  
  
    * [Node](#node.Node)
  

* [Scalar Value Types](#scalar-value-types)



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





 

 

 

 



<a name="node.proto"/>
<p align="right"><a href="#top">Top</a></p>

## node.proto
The Node API is exposed by the Spire Server to Node Agents.
A node agent uses this API to attest the node it is running on,
to retrieve the list of identities that are allowed to run on that node,
and to retrieve SVIDs by presenting certificate signing requests to the Spire Server.


<a name="node.FetchBaseSVIDRequest"/>

### FetchBaseSVIDRequest
Represents a request to attest the node.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attested_data | [.common.AttestedData](#node..common.AttestedData) |  | A type which contains attestation data for specific platform. |
| csr | [bytes](#bytes) |  | Certificate signing request. |






<a name="node.FetchBaseSVIDResponse"/>

### FetchBaseSVIDResponse
Represents a response that contains  map of signed SVIDs and an array of all current Registration Entries which are relevant to the caller SPIFFE ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| svid_update | [SvidUpdate](#node.SvidUpdate) |  | It includes a map of signed SVIDs and an array of all current Registration Entries which are relevant to the caller SPIFFE ID. |






<a name="node.FetchCPBundleRequest"/>

### FetchCPBundleRequest
Represents an empty message.






<a name="node.FetchCPBundleResponse"/>

### FetchCPBundleResponse
Represents a response with a Spire Server certificate bundle.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| server_bundle | [bytes](#bytes) |  | Spire Server certificate bundle. |






<a name="node.FetchFederatedBundleRequest"/>

### FetchFederatedBundleRequest
Represents a request with an array of SPIFFE Ids.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) | repeated | An array of SPIFFE Ids. |






<a name="node.FetchFederatedBundleResponse"/>

### FetchFederatedBundleResponse
Represents a response with a map of SPIFFE Id, Federated CA Bundle.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| federated_bundles | [FetchFederatedBundleResponse.FederatedBundlesEntry](#node.FetchFederatedBundleResponse.FederatedBundlesEntry) | repeated | Map [ SPIFFE ID ] =&gt; Federated CA Bundle |






<a name="node.FetchFederatedBundleResponse.FederatedBundlesEntry"/>

### FetchFederatedBundleResponse.FederatedBundlesEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [bytes](#bytes) |  |  |






<a name="node.FetchSVIDRequest"/>

### FetchSVIDRequest
Represents a request with a list of CSR.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| csrs | [bytes](#bytes) | repeated | A list of CSRs. |






<a name="node.FetchSVIDResponse"/>

### FetchSVIDResponse
Represents a response that contains  map of signed SVIDs and an array of all current Registration Entries which are relevant to the caller SPIFFE ID.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| svid_update | [SvidUpdate](#node.SvidUpdate) |  | It includes a map of signed SVIDs and an array of all current Registration Entries which are relevant to the caller SPIFFE ID. |






<a name="node.Svid"/>

### Svid
A type which contains the &#34;Spiffe Verifiable Identity Document&#34; and a TTL indicating when the SVID expires.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| svid_cert | [bytes](#bytes) |  | Spiffe Verifiable Identity Document. |
| ttl | [int32](#int32) |  | SVID expiration. |






<a name="node.SvidUpdate"/>

### SvidUpdate
A message returned by the Spire Server, which includes a map of signed SVIDs and
a list of all current Registration Entries which are relevant to the caller SPIFFE ID.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| svids | [SvidUpdate.SvidsEntry](#node.SvidUpdate.SvidsEntry) | repeated | A map containing SVID values and corresponding SPIFFE IDs as the keys. Map[SPIFFE_ID] =&gt; SVID. |
| registration_entries | [.common.RegistrationEntry](#node..common.RegistrationEntry) | repeated | A type representing a curated record that the Spire Server uses to set up and manage the various registered nodes and workloads that are controlled by it. |






<a name="node.SvidUpdate.SvidsEntry"/>

### SvidUpdate.SvidsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [Svid](#node.Svid) |  |  |





 

 

 


<a name="node.Node"/>

### Node


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| FetchBaseSVID | [FetchBaseSVIDRequest](#node.FetchBaseSVIDRequest) | [FetchBaseSVIDResponse](#node.FetchBaseSVIDRequest) | Attest the node, get base node SVID. |
| FetchSVID | [FetchSVIDRequest](#node.FetchSVIDRequest) | [FetchSVIDResponse](#node.FetchSVIDRequest) | Get Workload, Node Agent certs and CA trust bundles. Also used for rotation(Base Node SVID or the Registered Node SVID used for this call)(List can be empty to allow Node Agent cache refresh). |
| FetchCPBundle | [FetchCPBundleRequest](#node.FetchCPBundleRequest) | [FetchCPBundleResponse](#node.FetchCPBundleRequest) | Called by Node Agent periodically to support Spire Server certificate rotation. Cached in Node Agent memory for WorkLoads as well. |
| FetchFederatedBundle | [FetchFederatedBundleRequest](#node.FetchFederatedBundleRequest) | [FetchFederatedBundleResponse](#node.FetchFederatedBundleRequest) | Called by the Node Agent to fetch the named Federated CA Bundle.Used in the event that authorized workloads reference a Federated Bundle. |

 



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

