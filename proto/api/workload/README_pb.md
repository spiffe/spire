# Protocol Documentation
<a name="top"/>

## Table of Contents

- [struct.proto](#struct.proto)
    - [ListValue](#google.protobuf.ListValue)
    - [Struct](#google.protobuf.Struct)
    - [Struct.FieldsEntry](#google.protobuf.Struct.FieldsEntry)
    - [Value](#google.protobuf.Value)
  
    - [NullValue](#google.protobuf.NullValue)
  
  
  

- [workload.proto](#workload.proto)
    - [JWTABundlesRequest](#.JWTABundlesRequest)
    - [JWTABundlesResponse](#.JWTABundlesResponse)
    - [JWTABundlesResponse.BundlesEntry](#.JWTABundlesResponse.BundlesEntry)
    - [JWTASVID](#.JWTASVID)
    - [JWTASVIDRequest](#.JWTASVIDRequest)
    - [JWTASVIDResponse](#.JWTASVIDResponse)
    - [ValidateJWTASVIDRequest](#.ValidateJWTASVIDRequest)
    - [ValidateJWTASVIDResponse](#.ValidateJWTASVIDResponse)
    - [X509SVID](#.X509SVID)
    - [X509SVIDRequest](#.X509SVIDRequest)
    - [X509SVIDResponse](#.X509SVIDResponse)
    - [X509SVIDResponse.FederatedBundlesEntry](#.X509SVIDResponse.FederatedBundlesEntry)
  
  
  
    - [SpiffeWorkloadAPI](#.SpiffeWorkloadAPI)
  

- [Scalar Value Types](#scalar-value-types)



<a name="struct.proto"/>
<p align="right"><a href="#top">Top</a></p>

## struct.proto



<a name="google.protobuf.ListValue"/>

### ListValue
`ListValue` is a wrapper around a repeated field of values.

The JSON representation for `ListValue` is JSON array.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| values | [Value](#google.protobuf.Value) | repeated | Repeated field of dynamically typed values. |






<a name="google.protobuf.Struct"/>

### Struct
`Struct` represents a structured data value, consisting of fields
which map to dynamically typed values. In some languages, `Struct`
might be supported by a native representation. For example, in
scripting languages like JS a struct is represented as an
object. The details of that representation are described together
with the proto support for the language.

The JSON representation for `Struct` is JSON object.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| fields | [Struct.FieldsEntry](#google.protobuf.Struct.FieldsEntry) | repeated | Unordered map of dynamically typed values. |






<a name="google.protobuf.Struct.FieldsEntry"/>

### Struct.FieldsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [Value](#google.protobuf.Value) |  |  |






<a name="google.protobuf.Value"/>

### Value
`Value` represents a dynamically typed value which can be either
null, a number, a string, a boolean, a recursive struct value, or a
list of values. A producer of value is expected to set one of that
variants, absence of any variant indicates an error.

The JSON representation for `Value` is JSON value.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| null_value | [NullValue](#google.protobuf.NullValue) |  | Represents a null value. |
| number_value | [double](#double) |  | Represents a double value. |
| string_value | [string](#string) |  | Represents a string value. |
| bool_value | [bool](#bool) |  | Represents a boolean value. |
| struct_value | [Struct](#google.protobuf.Struct) |  | Represents a structured value. |
| list_value | [ListValue](#google.protobuf.ListValue) |  | Represents a repeated `Value`. |





 


<a name="google.protobuf.NullValue"/>

### NullValue
`NullValue` is a singleton enumeration to represent the null value for the
`Value` type union.

The JSON representation for `NullValue` is JSON `null`.

| Name | Number | Description |
| ---- | ------ | ----------- |
| NULL_VALUE | 0 | Null value. |


 

 

 



<a name="workload.proto"/>
<p align="right"><a href="#top">Top</a></p>

## workload.proto



<a name=".JWTABundlesRequest"/>

### JWTABundlesRequest







<a name=".JWTABundlesResponse"/>

### JWTABundlesResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundles | [.JWTABundlesResponse.BundlesEntry](#..JWTABundlesResponse.BundlesEntry) | repeated | JWK sets, keyed by trust domain URI |






<a name=".JWTABundlesResponse.BundlesEntry"/>

### JWTABundlesResponse.BundlesEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [bytes](#bytes) |  |  |






<a name=".JWTASVID"/>

### JWTASVID



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  |  |
| svid | [string](#string) |  | Encoded using JWS Compact Serialization |






<a name=".JWTASVIDRequest"/>

### JWTASVIDRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| audience | [string](#string) | repeated |  |
| spiffe_id | [string](#string) |  | SPIFFE ID of the JWT being requested If not set, all IDs will be returned |






<a name=".JWTASVIDResponse"/>

### JWTASVIDResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| svids | [.JWTASVID](#..JWTASVID) | repeated |  |






<a name=".ValidateJWTASVIDRequest"/>

### ValidateJWTASVIDRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| audience | [string](#string) | repeated |  |
| svid | [string](#string) |  | Encoded using JWS Compact Serialization |






<a name=".ValidateJWTASVIDResponse"/>

### ValidateJWTASVIDResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  |  |
| claims | [.google.protobuf.Struct](#..google.protobuf.Struct) |  |  |






<a name=".X509SVID"/>

### X509SVID
The X509SVID message carries a single SVID and all associated
information, including CA bundles.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| spiffe_id | [string](#string) |  | The SPIFFE ID of the SVID in this entry |
| x509_svid | [bytes](#bytes) |  | ASN.1 DER encoded certificate chain. MAY include intermediates, the leaf certificate (or SVID itself) MUST come first. |
| x509_svid_key | [bytes](#bytes) |  | ASN.1 DER encoded PKCS#8 private key. MUST be unencrypted. |
| bundle | [bytes](#bytes) |  | CA certificates belonging to the Trust Domain ASN.1 DER encoded |
| federates_with | [string](#string) | repeated | List of trust domains the SVID federates with, which corresponds to keys in the federated_bundles map in the X509SVIDResponse message. |






<a name=".X509SVIDRequest"/>

### X509SVIDRequest







<a name=".X509SVIDResponse"/>

### X509SVIDResponse
The X509SVIDResponse message carries a set of X.509 SVIDs and their
associated information. It also carries a set of global CRLs, and a
TTL to inform the workload when it should check back next.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| svids | [.X509SVID](#..X509SVID) | repeated | A list of X509SVID messages, each of which includes a single SPIFFE Verifiable Identity Document, along with its private key and bundle. |
| crl | [bytes](#bytes) | repeated | ASN.1 DER encoded |
| federated_bundles | [.X509SVIDResponse.FederatedBundlesEntry](#..X509SVIDResponse.FederatedBundlesEntry) | repeated | CA certificate bundles belonging to foreign Trust Domains that the workload should trust, keyed by the SPIFFE ID of the foreign domain. Bundles are ASN.1 DER encoded. |






<a name=".X509SVIDResponse.FederatedBundlesEntry"/>

### X509SVIDResponse.FederatedBundlesEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [bytes](#bytes) |  |  |





 

 

 


<a name=".SpiffeWorkloadAPI"/>

### SpiffeWorkloadAPI


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| FetchJWTASVID | [JWTASVIDRequest](#JWTASVIDRequest) | [JWTASVIDResponse](#JWTASVIDRequest) | JWT-SVID Profile |
| FetchJWTABundles | [JWTABundlesRequest](#JWTABundlesRequest) | [JWTABundlesResponse](#JWTABundlesRequest) |  |
| ValidateJWTASVID | [ValidateJWTASVIDRequest](#ValidateJWTASVIDRequest) | [ValidateJWTASVIDResponse](#ValidateJWTASVIDRequest) |  |
| FetchX509SVID | [X509SVIDRequest](#X509SVIDRequest) | [X509SVIDResponse](#X509SVIDRequest) | X.509-SVID Profile Fetch all SPIFFE identities the workload is entitled to, as well as related information like trust bundles and CRLs. As this information changes, subsequent messages will be sent. |

 



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

