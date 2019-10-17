# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [upstreamca.proto](#upstreamca.proto)
    - [SignedCertificate](#spire.server.upstreamca.SignedCertificate)
    - [SubmitCSRRequest](#spire.server.upstreamca.SubmitCSRRequest)
    - [SubmitCSRResponse](#spire.server.upstreamca.SubmitCSRResponse)
  
  
  
    - [UpstreamCA](#spire.server.upstreamca.UpstreamCA)
  

- [Scalar Value Types](#scalar-value-types)



<a name="upstreamca.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## upstreamca.proto



<a name="spire.server.upstreamca.SignedCertificate"></a>

### SignedCertificate



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cert_chain | [bytes](#bytes) |  | Contains ASN.1 encoded certificates representing the signed certificate along with any intermediates necessary to chain the certificate back to a certificate present in the upstream_trust_bundle. |
| bundle | [bytes](#bytes) |  | The upstream trust bundle. |






<a name="spire.server.upstreamca.SubmitCSRRequest"></a>

### SubmitCSRRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| csr | [bytes](#bytes) |  | Certificate signing request |
| preferred_ttl | [int32](#int32) |  | Preferred TTL is the TTL preferred by SPIRE server for signed CA. If zero, the plugin should determine its own TTL value. Upstream CA plugins are free to ignore this and use their own policies around TTLs. |






<a name="spire.server.upstreamca.SubmitCSRResponse"></a>

### SubmitCSRResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| signed_certificate | [SignedCertificate](#spire.server.upstreamca.SignedCertificate) |  | Signed certificate |





 

 

 


<a name="spire.server.upstreamca.UpstreamCA"></a>

### UpstreamCA


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Configure | [.spire.common.plugin.ConfigureRequest](#spire.common.plugin.ConfigureRequest) | [.spire.common.plugin.ConfigureResponse](#spire.common.plugin.ConfigureResponse) | Responsible for configuration of the plugin. |
| GetPluginInfo | [.spire.common.plugin.GetPluginInfoRequest](#spire.common.plugin.GetPluginInfoRequest) | [.spire.common.plugin.GetPluginInfoResponse](#spire.common.plugin.GetPluginInfoResponse) | Returns the version and related metadata of the installed plugin. */ |
| SubmitCSR | [SubmitCSRRequest](#spire.server.upstreamca.SubmitCSRRequest) | [SubmitCSRResponse](#spire.server.upstreamca.SubmitCSRResponse) | Signs a certificate from the request |

 



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

