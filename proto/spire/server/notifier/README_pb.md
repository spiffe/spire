# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [notifier.proto](#notifier.proto)
    - [BundleLoaded](#spire.server.notifier.BundleLoaded)
    - [BundleUpdated](#spire.server.notifier.BundleUpdated)
    - [NotifyAndAdviseRequest](#spire.server.notifier.NotifyAndAdviseRequest)
    - [NotifyAndAdviseResponse](#spire.server.notifier.NotifyAndAdviseResponse)
    - [NotifyRequest](#spire.server.notifier.NotifyRequest)
    - [NotifyResponse](#spire.server.notifier.NotifyResponse)
  
  
  
    - [Notifier](#spire.server.notifier.Notifier)
  

- [Scalar Value Types](#scalar-value-types)



<a name="notifier.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## notifier.proto



<a name="spire.server.notifier.BundleLoaded"></a>

### BundleLoaded



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [spire.common.Bundle](#spire.common.Bundle) |  |  |






<a name="spire.server.notifier.BundleUpdated"></a>

### BundleUpdated



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle | [spire.common.Bundle](#spire.common.Bundle) |  |  |






<a name="spire.server.notifier.NotifyAndAdviseRequest"></a>

### NotifyAndAdviseRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle_loaded | [BundleLoaded](#spire.server.notifier.BundleLoaded) |  | BundleLoaded is emitted on startup after SPIRE server creates/loads the trust bundle. If an error is returned SPIRE server is shut down. |






<a name="spire.server.notifier.NotifyAndAdviseResponse"></a>

### NotifyAndAdviseResponse







<a name="spire.server.notifier.NotifyRequest"></a>

### NotifyRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bundle_updated | [BundleUpdated](#spire.server.notifier.BundleUpdated) |  | BundleUpdated is emitted whenever SPIRE server changes the trust bundle. |






<a name="spire.server.notifier.NotifyResponse"></a>

### NotifyResponse






 

 

 


<a name="spire.server.notifier.Notifier"></a>

### Notifier


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Notify | [NotifyRequest](#spire.server.notifier.NotifyRequest) | [NotifyResponse](#spire.server.notifier.NotifyResponse) | Notify notifies the plugin that an event occurred. Errors returned by the plugin are logged but otherwise ignored. |
| NotifyAndAdvise | [NotifyAndAdviseRequest](#spire.server.notifier.NotifyAndAdviseRequest) | [NotifyAndAdviseResponse](#spire.server.notifier.NotifyAndAdviseResponse) | NotifyAndAdvise notifies the plugin that an event occurred and waits for a response. Errors returned by the plugin control SPIRE server behavior. See NotifyAndAdviseRequest for per-event details. |
| Configure | [.spire.common.plugin.ConfigureRequest](#spire.common.plugin.ConfigureRequest) | [.spire.common.plugin.ConfigureResponse](#spire.common.plugin.ConfigureResponse) |  |
| GetPluginInfo | [.spire.common.plugin.GetPluginInfoRequest](#spire.common.plugin.GetPluginInfoRequest) | [.spire.common.plugin.GetPluginInfoResponse](#spire.common.plugin.GetPluginInfoResponse) |  |

 



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

