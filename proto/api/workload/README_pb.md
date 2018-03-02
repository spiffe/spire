# Protocol Documentation
<a name="top"/>

## Table of Contents

- [workload.proto](#workload.proto)
    - [X509SVID](#.X509SVID)
    - [X509SVIDRequest](#.X509SVIDRequest)
    - [X509SVIDResponse](#.X509SVIDResponse)
    - [X509SVIDResponse.FederatedBundlesEntry](#.X509SVIDResponse.FederatedBundlesEntry)
  
  
  
    - [SpiffeWorkloadAPI](#.SpiffeWorkloadAPI)
  

- [Scalar Value Types](#scalar-value-types)



<a name="workload.proto"/>
<p align="right"><a href="#top">Top</a></p>

## workload.proto



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

