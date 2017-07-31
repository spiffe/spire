# Protocol Documentation
<a name="top"/>

## Table of Contents
* [workload.proto](#workload.proto)
 * [FederateEntry](#proto.FederateEntry)
 * [FetchFederatedBundleRequest](#proto.FetchFederatedBundleRequest)
 * [FetchFederatedBundleResponse](#proto.FetchFederatedBundleResponse)
 * [FetchFederatedBundlesResponse](#proto.FetchFederatedBundlesResponse)
 * [FetchSVIDBundleRequest](#proto.FetchSVIDBundleRequest)
 * [FetchSVIDBundleResponse](#proto.FetchSVIDBundleResponse)
 * [FetchSVIDBundlesResponse](#proto.FetchSVIDBundlesResponse)
 * [WLSVIDEntry](#proto.WLSVIDEntry)
 * [Workload](#proto.Workload)
* [Scalar Value Types](#scalar-value-types)

<a name="workload.proto"/>
<p align="right"><a href="#top">Top</a></p>

## workload.proto

A workload uses this API to retrieve a list of identities that it should be allowed
to represent itself as (SPIFFE IDs) as well as, optionally, documents (in the form of
SPIFFE Verifiable Identity Documents(SVID) ) that can be used to prove those identities to other systems.

Finally, the API can also be used to retrieve trust bundles that can be used to
verify SVIDs from other SPIFFE-identified workloads.

<a name="proto.FederateEntry"/>

### FederateEntry
| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeId | [string](#string) | optional | spiffeid of the remote workload |
| caTrustBundle | [bytes](#bytes) | optional | ASN.1 DER encoded cert bundle |
| ttl | [int32](#int32) | optional | Controls how often a workload consuming this cert bundle should check back for updates. |


<a name="proto.FetchFederatedBundleRequest"/>

### FetchFederatedBundleRequest
represents a Federated cert Bundle request corresponding to a specific SPIFFEId

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeId | [string](#string) | optional |  |


<a name="proto.FetchFederatedBundleResponse"/>

### FetchFederatedBundleResponse
represents cert Bundles that a specific workload's SPIFFEId is registered to trust

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| FederateEntry | [FederateEntry](#proto.FederateEntry) | repeated | trusted external CA cert bundles of foreign control planes |


<a name="proto.FetchFederatedBundlesResponse"/>

### FetchFederatedBundlesResponse
represents all the cert Bundles that a workload is registered to trust

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| FederateEntry | [FederateEntry](#proto.FederateEntry) | repeated | trusted external CA cert bundles of foreign control planes |


<a name="proto.FetchSVIDBundleRequest"/>

### FetchSVIDBundleRequest
represents a workload request for a SVID and the control plane's cert bundle of a specific SPIFFEID

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeId | [string](#string) | optional |  |


<a name="proto.FetchSVIDBundleResponse"/>

### FetchSVIDBundleResponse
represents a response specific to the requesting workload SPIFFEId,
Includes the workload's SVID Entry(SVID and its corresponding information )
and the Control Plane's trusted cert bundle

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| WLSVIDEntry | [WLSVIDEntry](#proto.WLSVIDEntry) | optional | Workload's SVID Entry |
| cpBundle | [bytes](#bytes) | optional | Control Plane's trusted cert bundle |


<a name="proto.FetchSVIDBundlesResponse"/>

### FetchSVIDBundlesResponse
represents response the includes all the SVIDs the and Control Plane's trusted cert bundle workload

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| WLSVIDEntry | [WLSVIDEntry](#proto.WLSVIDEntry) | repeated | list of Workload SVID entries |
| cpBundle | [bytes](#bytes) | optional | Control Plane's trusted cert bundle |


<a name="proto.WLSVIDEntry"/>

### WLSVIDEntry
A WLSVIDEntry represents a Workload's SVID and its associated information

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeId | [string](#string) | optional | SPIFFE Id corresponding to the SVID |
| svid | [bytes](#bytes) | optional | ASN.1 DER encoded SVID |
| privateKey | [bytes](#bytes) | optional | private key corresponding to the SVID |
| ttl | [int32](#int32) | optional | Controls how often a workload associated with this SVID should check back for updates. |





<a name="proto.Workload"/>

### Workload
| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| FetchSVIDBundle | [FetchSVIDBundleRequest](#proto.FetchSVIDBundleRequest) | [FetchSVIDBundleResponse](#proto.FetchSVIDBundleResponse) | Requests SVID and cert bundle of the control plane corresponding to a specific SPIFFEId(useful for rotation) |
| FetchSVIDBundles | [Empty](#proto.Empty) | [FetchSVIDBundlesResponse](#proto.FetchSVIDBundlesResponse) | Requests all SVIDs and cert bundle of the control plane associated with the workload |
| FetchFederatedBundle | [FetchFederatedBundleRequest](#proto.FetchFederatedBundleRequest) | [FetchFederatedBundleResponse](#proto.FetchFederatedBundleResponse) | Requests trusted external CA cert bundles corresponding to a specific SPIFFEId (useful for rotation) |
| FetchFederatedBundles | [Empty](#proto.Empty) | [FetchFederatedBundlesResponse](#proto.FetchFederatedBundlesResponse) | Requests all trusted external CA cert bundles associated with the workload |



<a name="scalar-value-types"/>

## Scalar Value Types
| .proto Type | Notes | C++ Type | Java Type | Python Type |
| ----------- | ----- | -------- | --------- | ----------- |
| <a name="double"/> double |  | double | double | float |
| <a name="float"/> float |  | float | float | float |
| <a name="int32"/> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int |
| <a name="int64"/> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long |
| <a name="uint32"/> uint32 | Uses variable-length encoding. | uint32 | int | int/long |
| <a name="uint64"/> uint64 | Uses variable-length encoding. | uint64 | long | int/long |
| <a name="sint32"/> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int |
| <a name="sint64"/> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long |
| <a name="fixed32"/> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int |
| <a name="fixed64"/> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long |
| <a name="sfixed32"/> sfixed32 | Always four bytes. | int32 | int | int |
| <a name="sfixed64"/> sfixed64 | Always eight bytes. | int64 | long | int/long |
| <a name="bool"/> bool |  | bool | boolean | boolean |
| <a name="string"/> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode |
| <a name="bytes"/> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str |
