# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [identityprovider.proto](#identityprovider.proto)
    - [FetchX509IdentityRequest](#spire.server.hostservices.FetchX509IdentityRequest)
    - [FetchX509IdentityResponse](#spire.server.hostservices.FetchX509IdentityResponse)
    - [X509Identity](#spire.server.hostservices.X509Identity)
  
  
  
    - [IdentityProvider](#spire.server.hostservices.IdentityProvider)
  

- [agentstore.proto](#agentstore.proto)
    - [AgentInfo](#spire.server.hostservices.AgentInfo)
    - [GetAgentInfoRequest](#spire.server.hostservices.GetAgentInfoRequest)
    - [GetAgentInfoResponse](#spire.server.hostservices.GetAgentInfoResponse)
  
  
  
    - [AgentStore](#spire.server.hostservices.AgentStore)
  

- [Scalar Value Types](#scalar-value-types)



<a name="identityprovider.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## identityprovider.proto



<a name="spire.server.hostservices.FetchX509IdentityRequest"></a>

### FetchX509IdentityRequest







<a name="spire.server.hostservices.FetchX509IdentityResponse"></a>

### FetchX509IdentityResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| identity | [X509Identity](#spire.server.hostservices.X509Identity) |  |  |
| bundle | [spire.common.Bundle](#spire.common.Bundle) |  |  |






<a name="spire.server.hostservices.X509Identity"></a>

### X509Identity



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cert_chain | [bytes](#bytes) | repeated |  |
| private_key | [bytes](#bytes) |  |  |





 

 

 


<a name="spire.server.hostservices.IdentityProvider"></a>

### IdentityProvider


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| FetchX509Identity | [FetchX509IdentityRequest](#spire.server.hostservices.FetchX509IdentityRequest) | [FetchX509IdentityResponse](#spire.server.hostservices.FetchX509IdentityResponse) |  |

 



<a name="agentstore.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## agentstore.proto



<a name="spire.server.hostservices.AgentInfo"></a>

### AgentInfo



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| agent_id | [string](#string) |  |  |






<a name="spire.server.hostservices.GetAgentInfoRequest"></a>

### GetAgentInfoRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| agent_id | [string](#string) |  |  |






<a name="spire.server.hostservices.GetAgentInfoResponse"></a>

### GetAgentInfoResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| info | [AgentInfo](#spire.server.hostservices.AgentInfo) |  |  |





 

 

 


<a name="spire.server.hostservices.AgentStore"></a>

### AgentStore


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| GetAgentInfo | [GetAgentInfoRequest](#spire.server.hostservices.GetAgentInfoRequest) | [GetAgentInfoResponse](#spire.server.hostservices.GetAgentInfoResponse) |  |

 



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

