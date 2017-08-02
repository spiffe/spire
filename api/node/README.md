# Protocol Documentation
<a name="top"/>

## Table of Contents

* [node.proto](#node.proto)
* [AttestedData](#pb.AttestedData)
* [FetchBaseSVIDRequest](#pb.FetchBaseSVIDRequest)
* [FetchBaseSVIDResponse](#pb.FetchBaseSVIDResponse)
* [FetchCPBundleResponse](#pb.FetchCPBundleResponse)
* [FetchFederatedBundleRequest](#pb.FetchFederatedBundleRequest)
* [FetchFederatedBundleResponse](#pb.FetchFederatedBundleResponse)
* [FetchFederatedBundleResponse.MapEntry](#pb.FetchFederatedBundleResponse.MapEntry)
* [FetchSVIDRequest](#pb.FetchSVIDRequest)
* [FetchSVIDResponse](#pb.FetchSVIDResponse)
* [RegistrationEntry](#pb.RegistrationEntry)
* [Svid](#pb.Svid)
* [SvidMap](#pb.SvidMap)
* [SvidMap.MapEntry](#pb.SvidMap.MapEntry)
* [SvidUpdate](#pb.SvidUpdate)
* [node](#pb.node)
* [Scalar Value Types](#scalar-value-types)

<a name="node.proto"/>
<p align="right"><a href="#top">Top</a></p>

## node.proto

The Node API is exposed by the Control Plane to Node Agents.
A node agent uses this API to attest the node it is running on,
to retrieve the list of identities that are allowed to run on that node,
and to retrieve SVIDs by presenting certificate signing requests to the Control Plane.

<a name="pb.AttestedData"/>

### AttestedData

A type which contains attestation data for specific platform.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [string](#string) | optional | Type of attestation to perform. |
| data | [string](#string) | optional | The attestetion data. |


<a name="pb.FetchBaseSVIDRequest"/>

### FetchBaseSVIDRequest

Represents a request to attest the node.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| attestedData | [AttestedData](#pb.AttestedData) | optional | A type which contains attestation data for specific platform. |
| csr | [bytes](#bytes) | optional |  |


<a name="pb.FetchBaseSVIDResponse"/>

### FetchBaseSVIDResponse

Represents a response that contains  map of signed SVIDs and an array of all current Registration Entries which are relevant to the caller SPIFFE ID

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeEntry | [SvidUpdate](#pb.SvidUpdate) | optional | It includes a map of signed SVIDs and an array of all current Registration Entries which are relevant to the caller SPIFFE ID. |


<a name="pb.FetchCPBundleRequest"/>

### FetchCPBundleRequest

Represents an empty message.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |


<a name="pb.FetchCPBundleResponse"/>

### FetchCPBundleResponse

Represents a response with a Control Plane certificate bundle.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cpBundle | [bytes](#bytes) | optional | Control Plane certificate bundle. |


<a name="pb.FetchFederatedBundleRequest"/>

### FetchFederatedBundleRequest

Represents a request with an array of SPIFFE Ids.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeId | [string](#string) | repeated | An array of SPIFFE Ids. |


<a name="pb.FetchFederatedBundleResponse"/>

### FetchFederatedBundleResponse

Represents a response with a map of SPIFFE Id, Federated CA Bundle.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| map | [FetchFederatedBundleResponse.MapEntry](#pb.FetchFederatedBundleResponse.MapEntry) | repeated | Map [ SPIFFE ID ] => Federated CA Bundle |


<a name="pb.FetchFederatedBundleResponse.MapEntry"/>

### FetchFederatedBundleResponse.MapEntry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) | optional |  |
| value | [bytes](#bytes) | optional |  |


<a name="pb.FetchSVIDRequest"/>

### FetchSVIDRequest

Represents a request with a list of CSR.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| csrList | [bytes](#bytes) | repeated | A list of CSRs. |


<a name="pb.FetchSVIDResponse"/>

### FetchSVIDResponse

Represents a response that contains  map of signed SVIDs and an array of all current Registration Entries which are relevant to the caller SPIFFE ID.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffeEntry | [SvidUpdate](#pb.SvidUpdate) | optional | It includes a map of signed SVIDs and an array of all current Registration Entries which are relevant to the caller SPIFFE ID. |


<a name="pb.RegistrationEntry"/>

### RegistrationEntry

A type representing a curated record that the Control Plane uses to set up and manage the various registered nodes and workloads that are controlled by it.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selectorType | [string](#string) | optional | A selector type represents the type of attestation used in attesting the entity (Eg: AWS, K8). |
| selector | [string](#string) | optional | A native property of an entity. |
| spiffeId | [string](#string) | optional | An SPIFFE Id. |
| parentId | [string](#string) | optional | The SPIFFE ID of an entity that is authorized to attest the validity of a selector. |
| federatedSpiffeId | [string](#string) | repeated | A SPIFFE ID that has a Federated Bundle. |
| ttl | [int32](#int32) | optional | Time to live. |
| selectorGroup | [string](#string) | optional | Selector Group contains a GUID which allows for compounding selectors. In the case where a workload must satisfy multiple selectors in order to be issued a SPIFFE ID, the Registration Entries will share a Selector Group GUID. |


<a name="pb.Svid"/>

### Svid

A type which contains the "Spiffe Verifiable Identity Document" and a TTL indicating when the SVID expires.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| svidCert | [bytes](#bytes) | optional | Spiffe Verifiable Identity Document. |
| ttl | [int32](#int32) | optional | SVID expiration. |


<a name="pb.SvidMap"/>

### SvidMap

A map containing SVID values and corresponding SPIFFE IDs as the keys.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| map | [SvidMap.MapEntry](#pb.SvidMap.MapEntry) | repeated | Map[SPIFFE_ID] => SVID |


<a name="pb.SvidMap.MapEntry"/>

### SvidMap.MapEntry


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) | optional |  |
| value | [Svid](#pb.Svid) | optional |  |


<a name="pb.SvidUpdate"/>

### SvidUpdate

A message returned by the Control Plane, which includes a map of signed SVIDs and
an array of all current Registration Entries which are relevant to the caller SPIFFE ID.

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| svidMap | [SvidMap](#pb.SvidMap) | optional | A map containing SVID values and corresponding SPIFFE IDs as the keys. |
| registrationEntryList | [RegistrationEntry](#pb.RegistrationEntry) | repeated | A type representing a curated record that the Control Plane uses to set up and manage the various registered nodes and workloads that are controlled by it. |

<a name="pb.node"/>

### node


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| FetchBaseSVID | [FetchBaseSVIDRequest](#pb.FetchBaseSVIDRequest) | [FetchBaseSVIDResponse](#pb.FetchBaseSVIDResponse) | Attest the node, get base node SVID. |
| FetchSVID | [FetchSVIDRequest](#pb.FetchSVIDRequest) | [FetchSVIDResponse](#pb.FetchSVIDResponse) | Get Workload, Node Agent certs and CA trust bundles. Also used for rotation/(Base Node SVID or the Registered Node SVID used for this call)/(List can be empty to allow Node Agent cache refresh). |
| FetchCPBundle | [Empty](#pb.Empty) | [FetchCPBundleResponse](#pb.FetchCPBundleResponse) | Called by Node Agent periodically to support Control Plane certificate rotation. Cached in Node Agent memory for WorkLoads as well. |
| FetchFederatedBundle | [FetchFederatedBundleRequest](#pb.FetchFederatedBundleRequest) | [FetchFederatedBundleResponse](#pb.FetchFederatedBundleResponse) | Called by the Node Agent to fetch the named Federated CA Bundle./Used in the event that authorized workloads reference a Federated Bundle. |



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
