# Protocol Documentation
<a name="top"/>

## Table of Contents


* [workload.proto](#workload.proto)
  
    * [Bundles](#spire.api.workload.Bundles)
  
    * [Empty](#spire.api.workload.Empty)
  
    * [SpiffeID](#spire.api.workload.SpiffeID)
  
    * [WorkloadEntry](#spire.api.workload.WorkloadEntry)
  
    * [WorkloadEntry.FederatedBundlesEntry](#spire.api.workload.WorkloadEntry.FederatedBundlesEntry)
  
  
  
  
    * [Workload](#spire.api.workload.Workload)
  

* [Scalar Value Types](#scalar-value-types)



<a name="workload.proto"/>
<p align="right"><a href="#top">Top</a></p>

## workload.proto



<a name="spire.api.workload.Bundles"/>

### Bundles
The Bundles message carries a group of workload SVIDs and their
associated information. It also carries a TTL to inform the workload
when it should check back next.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundles | [WorkloadEntry](#spire.api.workload.WorkloadEntry) | repeated |  |
| ttl | [int32](#int32) |  |  |






<a name="spire.api.workload.Empty"/>

### Empty
Represents a message with no fields






<a name="spire.api.workload.SpiffeID"/>

### SpiffeID
The SpiffeID message carries only a SPIFFE ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  |  |






<a name="spire.api.workload.WorkloadEntry"/>

### WorkloadEntry
The WorkloadEntry message carries a single SVID and all associated
information, including CA bundles. All `bytes` types are ASN.1 DER encoded


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  | The SPIFFE ID of the SVID in this entry |
| svid | [bytes](#bytes) |  | The SVID itself |
| svid_private_key | [bytes](#bytes) |  | The SVID private key |
| svid_bundle | [bytes](#bytes) |  | CA certificates belonging to the SVID |
| federated_bundles | [WorkloadEntry.FederatedBundlesEntry](#spire.api.workload.WorkloadEntry.FederatedBundlesEntry) | repeated | CA certificates that the workload should trust, mappedby the trust domain of the external authority |






<a name="spire.api.workload.WorkloadEntry.FederatedBundlesEntry"/>

### WorkloadEntry.FederatedBundlesEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [bytes](#bytes) |  |  |





 

 

 


<a name="spire.api.workload.Workload"/>

### Workload


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| FetchBundles | [SpiffeID](#spire.api.workload.SpiffeID) | [Bundles](#spire.api.workload.SpiffeID) | Fetch bundles for the SVID with the given SPIFFE ID |
| FetchAllBundles | [Empty](#spire.api.workload.Empty) | [Bundles](#spire.api.workload.Empty) | Fetch all bundles the workload is entitled to |

 



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

