# Protocol Documentation
<a name="top"/>

## Table of Contents


* [workload.proto](#workload.proto)
  
    * [Empty](#spire.api.workload.Empty)
  
    * [FederateEntry](#spire.api.workload.FederateEntry)
  
    * [FetchFederatedBundleRequest](#spire.api.workload.FetchFederatedBundleRequest)
  
    * [FetchFederatedBundleResponse](#spire.api.workload.FetchFederatedBundleResponse)
  
    * [FetchFederatedBundlesResponse](#spire.api.workload.FetchFederatedBundlesResponse)
  
    * [FetchSVIDBundleRequest](#spire.api.workload.FetchSVIDBundleRequest)
  
    * [FetchSVIDBundleResponse](#spire.api.workload.FetchSVIDBundleResponse)
  
    * [FetchSVIDBundlesResponse](#spire.api.workload.FetchSVIDBundlesResponse)
  
    * [WLSVIDEntry](#spire.api.workload.WLSVIDEntry)
  
  
  
  
    * [Workload](#spire.api.workload.Workload)
  

* [Scalar Value Types](#scalar-value-types)



<a name="workload.proto"/>
<p align="right"><a href="#top">Top</a></p>

## workload.proto



<a name="spire.api.workload.Empty"/>

### Empty
Represents a message with no fields






<a name="spire.api.workload.FederateEntry"/>

### FederateEntry
Represents cert bundle of a remote control plane for the purposes
of trusting remote workloads


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeId | [string](#string) |  | spiffeid of the remote workload |
| caTrustBundle | [bytes](#bytes) |  | ASN.1 DER encoded cert bundle |
| ttl | [int32](#int32) |  | Controls how often a workload consuming this cert bundle should check back for updates. |






<a name="spire.api.workload.FetchFederatedBundleRequest"/>

### FetchFederatedBundleRequest
Represents a Federated cert Bundle request corresponding to a
specific SPIFFEId


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeId | [string](#string) |  |  |






<a name="spire.api.workload.FetchFederatedBundleResponse"/>

### FetchFederatedBundleResponse
represents cert Bundles that a specific workload&#39;s SPIFFEId is
registered to trust


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| FederateEntry | [FederateEntry](#spire.api.workload.FederateEntry) | repeated | Trusted external CA cert bundles of foreign control planes |






<a name="spire.api.workload.FetchFederatedBundlesResponse"/>

### FetchFederatedBundlesResponse
Represents all the cert Bundles that a workload is registered to trust


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| FederateEntry | [FederateEntry](#spire.api.workload.FederateEntry) | repeated | Trusted external CA cert bundles of foreign control planes |






<a name="spire.api.workload.FetchSVIDBundleRequest"/>

### FetchSVIDBundleRequest
Represents a workload request for a SVID and the control plane&#39;s
cert bundle of a specific SPIFFEID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeId | [string](#string) |  |  |






<a name="spire.api.workload.FetchSVIDBundleResponse"/>

### FetchSVIDBundleResponse
Represents a response specific to the requesting workload SPIFFEId,
Includes the workload&#39;s SVID Entry (SVID and its corresponding information)
and the Control Plane&#39;s trusted cert bundle


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| WLSVIDEntry | [WLSVIDEntry](#spire.api.workload.WLSVIDEntry) |  | Workload&#39;s SVID Entry |
| cpBundle | [bytes](#bytes) |  | Control Plane&#39;s trusted cert bundle |






<a name="spire.api.workload.FetchSVIDBundlesResponse"/>

### FetchSVIDBundlesResponse
Represents response the includes all the SVIDs the and Control
Plane&#39;s trusted cert bundle workload


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| WLSVIDEntry | [WLSVIDEntry](#spire.api.workload.WLSVIDEntry) | repeated | list of Workload SVID entries |
| cpBundle | [bytes](#bytes) |  | Control Plane&#39;s trusted cert bundle |






<a name="spire.api.workload.WLSVIDEntry"/>

### WLSVIDEntry
A WLSVIDEntry represents a Workload&#39;s SVID and its associated
information


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeId | [string](#string) |  | SPIFFE Id corresponding to the SVID |
| svid | [bytes](#bytes) |  | ASN.1 DER encoded SVID |
| privateKey | [bytes](#bytes) |  | private key corresponding to the SVID |
| ttl | [int32](#int32) |  | Controls how often a workload associated with this SVID should check back for updates. |





 

 

 


<a name="spire.api.workload.Workload"/>

### Workload


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| FetchSVIDBundle | [FetchSVIDBundleRequest](#spire.api.workload.FetchSVIDBundleRequest) | [FetchSVIDBundleResponse](#spire.api.workload.FetchSVIDBundleRequest) | Requests SVID and cert bundle of the control plane corresponding to a specific SPIFFEId(useful for rotation) |
| FetchSVIDBundles | [Empty](#spire.api.workload.Empty) | [FetchSVIDBundlesResponse](#spire.api.workload.Empty) | Requests all SVIDs and cert bundle of the control plane associated with the workload |
| FetchFederatedBundle | [FetchFederatedBundleRequest](#spire.api.workload.FetchFederatedBundleRequest) | [FetchFederatedBundleResponse](#spire.api.workload.FetchFederatedBundleRequest) | Requests trusted external CA cert bundles corresponding to a specific SPIFFEId (useful for rotation) |
| FetchFederatedBundles | [Empty](#spire.api.workload.Empty) | [FetchFederatedBundlesResponse](#spire.api.workload.Empty) | Requests all trusted external CA cert bundles associated with the workload |

 



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

