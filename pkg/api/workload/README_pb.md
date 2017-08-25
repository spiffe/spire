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
  
  
  
  


* [workload.proto](#workload.proto)
  
    * [Bundles](#workload.Bundles)
  
    * [SpiffeId](#workload.SpiffeId)
  
    * [WorkloadEntry](#workload.WorkloadEntry)
  
    * [WorkloadEntry.FederatedBundlesEntry](#workload.WorkloadEntry.FederatedBundlesEntry)
  
  
  
  
    * [Workload](#workload.Workload)
  

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





 

 

 

 



<a name="workload.proto"/>
<p align="right"><a href="#top">Top</a></p>

## workload.proto
A workload uses this API to retrieve a list of identities that it should be allowed
to represent itself as (SPIFFE IDs) as well as, optionally, documents (in the form of
SPIFFE Verifiable Identity Documents (SVID) ) that can be used to prove those identities to other systems.

Finally, the API can also be used to retrieve trust bundles that can be used to
verify SVIDs from other SPIFFE-identified workloads.


<a name="workload.Bundles"/>

### Bundles
Represents a list of WorkloadEntry and a Control Plane bundle.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| workload_entry | [WorkloadEntry](#workload.WorkloadEntry) | repeated | Workload&#39;s SVID Entry /// trusted external CA cert bundles of foreign control planes |
| ttl | [int32](#int32) |  | Controls how often a workload associated with this SVID or cert bundle should check back for updates. |






<a name="workload.SpiffeId"/>

### SpiffeId
Represents and SPIFFEId that depending on its association it could be used to
request for a SVID and the control plane&#39;s cert bundle or request for a Federated cert Bundle.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  |  |






<a name="workload.WorkloadEntry"/>

### WorkloadEntry
Depending on the context it represents a Workload&#39;s SVID and its associated information
or a cert bundle of a remote control plane for the purposes of trusting remote workloads.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  | SPIFFE Id corresponding to the SVID. |
| svid | [bytes](#bytes) |  | ASN.1 DER encoded SVID. |
| svid_private_key | [bytes](#bytes) |  | Private key corresponding to the SVID. |
| control_plane_bundle | [bytes](#bytes) |  | Control Plane&#39;s trusted cert bundle. |
| federated_bundles | [WorkloadEntry.FederatedBundlesEntry](#workload.WorkloadEntry.FederatedBundlesEntry) | repeated | A map of SPIFFE ID =&gt; Federated Bundle (ASN.1 DER encoded cert bundle). |






<a name="workload.WorkloadEntry.FederatedBundlesEntry"/>

### WorkloadEntry.FederatedBundlesEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [bytes](#bytes) |  |  |





 

 

 


<a name="workload.Workload"/>

### Workload


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| FetchBundles | [SpiffeId](#workload.SpiffeId) | [Bundles](#workload.SpiffeId) | Depending on what the SPIFFEId is associated with,it requests SVID and cert bundle of the control plane corresponding to the SPIFFEIdor requests trusted external CA cert bundles corresponding to the SPIFFEId. |
| FetchAllBundles | [common.Empty](#common.Empty) | [Bundles](#common.Empty) | Requests all SVIDs and cert bundle of the control plane and all trusted external CA cert bundles associated with the workload. |

 



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

