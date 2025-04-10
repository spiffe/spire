// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v5.29.4
// source: spire/common/plugin/plugin.proto

package plugin

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// * Represents the plugin-specific configuration string.
type ConfigureRequest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// * The configuration for the plugin.
	Configuration string `protobuf:"bytes,1,opt,name=configuration,proto3" json:"configuration,omitempty"`
	// * Global configurations.
	GlobalConfig  *ConfigureRequest_GlobalConfig `protobuf:"bytes,2,opt,name=globalConfig,proto3" json:"globalConfig,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ConfigureRequest) Reset() {
	*x = ConfigureRequest{}
	mi := &file_spire_common_plugin_plugin_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ConfigureRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigureRequest) ProtoMessage() {}

func (x *ConfigureRequest) ProtoReflect() protoreflect.Message {
	mi := &file_spire_common_plugin_plugin_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfigureRequest.ProtoReflect.Descriptor instead.
func (*ConfigureRequest) Descriptor() ([]byte, []int) {
	return file_spire_common_plugin_plugin_proto_rawDescGZIP(), []int{0}
}

func (x *ConfigureRequest) GetConfiguration() string {
	if x != nil {
		return x.Configuration
	}
	return ""
}

func (x *ConfigureRequest) GetGlobalConfig() *ConfigureRequest_GlobalConfig {
	if x != nil {
		return x.GlobalConfig
	}
	return nil
}

// * Represents a list of configuration problems
// found in the configuration string.
type ConfigureResponse struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// * A list of errors
	ErrorList     []string `protobuf:"bytes,1,rep,name=errorList,proto3" json:"errorList,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ConfigureResponse) Reset() {
	*x = ConfigureResponse{}
	mi := &file_spire_common_plugin_plugin_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ConfigureResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigureResponse) ProtoMessage() {}

func (x *ConfigureResponse) ProtoReflect() protoreflect.Message {
	mi := &file_spire_common_plugin_plugin_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfigureResponse.ProtoReflect.Descriptor instead.
func (*ConfigureResponse) Descriptor() ([]byte, []int) {
	return file_spire_common_plugin_plugin_proto_rawDescGZIP(), []int{1}
}

func (x *ConfigureResponse) GetErrorList() []string {
	if x != nil {
		return x.ErrorList
	}
	return nil
}

// * Represents an empty request.
type GetPluginInfoRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetPluginInfoRequest) Reset() {
	*x = GetPluginInfoRequest{}
	mi := &file_spire_common_plugin_plugin_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetPluginInfoRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetPluginInfoRequest) ProtoMessage() {}

func (x *GetPluginInfoRequest) ProtoReflect() protoreflect.Message {
	mi := &file_spire_common_plugin_plugin_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetPluginInfoRequest.ProtoReflect.Descriptor instead.
func (*GetPluginInfoRequest) Descriptor() ([]byte, []int) {
	return file_spire_common_plugin_plugin_proto_rawDescGZIP(), []int{2}
}

// * Represents the plugin metadata.
type GetPluginInfoResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Name          string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Category      string                 `protobuf:"bytes,2,opt,name=category,proto3" json:"category,omitempty"`
	Type          string                 `protobuf:"bytes,3,opt,name=type,proto3" json:"type,omitempty"`
	Description   string                 `protobuf:"bytes,4,opt,name=description,proto3" json:"description,omitempty"`
	DateCreated   string                 `protobuf:"bytes,5,opt,name=dateCreated,proto3" json:"dateCreated,omitempty"`
	Location      string                 `protobuf:"bytes,6,opt,name=location,proto3" json:"location,omitempty"`
	Version       string                 `protobuf:"bytes,7,opt,name=version,proto3" json:"version,omitempty"`
	Author        string                 `protobuf:"bytes,8,opt,name=author,proto3" json:"author,omitempty"`
	Company       string                 `protobuf:"bytes,9,opt,name=company,proto3" json:"company,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetPluginInfoResponse) Reset() {
	*x = GetPluginInfoResponse{}
	mi := &file_spire_common_plugin_plugin_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetPluginInfoResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetPluginInfoResponse) ProtoMessage() {}

func (x *GetPluginInfoResponse) ProtoReflect() protoreflect.Message {
	mi := &file_spire_common_plugin_plugin_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetPluginInfoResponse.ProtoReflect.Descriptor instead.
func (*GetPluginInfoResponse) Descriptor() ([]byte, []int) {
	return file_spire_common_plugin_plugin_proto_rawDescGZIP(), []int{3}
}

func (x *GetPluginInfoResponse) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *GetPluginInfoResponse) GetCategory() string {
	if x != nil {
		return x.Category
	}
	return ""
}

func (x *GetPluginInfoResponse) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *GetPluginInfoResponse) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *GetPluginInfoResponse) GetDateCreated() string {
	if x != nil {
		return x.DateCreated
	}
	return ""
}

func (x *GetPluginInfoResponse) GetLocation() string {
	if x != nil {
		return x.Location
	}
	return ""
}

func (x *GetPluginInfoResponse) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *GetPluginInfoResponse) GetAuthor() string {
	if x != nil {
		return x.Author
	}
	return ""
}

func (x *GetPluginInfoResponse) GetCompany() string {
	if x != nil {
		return x.Company
	}
	return ""
}

type InitRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	HostServices  []string               `protobuf:"bytes,1,rep,name=host_services,json=hostServices,proto3" json:"host_services,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *InitRequest) Reset() {
	*x = InitRequest{}
	mi := &file_spire_common_plugin_plugin_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *InitRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InitRequest) ProtoMessage() {}

func (x *InitRequest) ProtoReflect() protoreflect.Message {
	mi := &file_spire_common_plugin_plugin_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InitRequest.ProtoReflect.Descriptor instead.
func (*InitRequest) Descriptor() ([]byte, []int) {
	return file_spire_common_plugin_plugin_proto_rawDescGZIP(), []int{4}
}

func (x *InitRequest) GetHostServices() []string {
	if x != nil {
		return x.HostServices
	}
	return nil
}

type InitResponse struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	PluginServices []string               `protobuf:"bytes,1,rep,name=plugin_services,json=pluginServices,proto3" json:"plugin_services,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *InitResponse) Reset() {
	*x = InitResponse{}
	mi := &file_spire_common_plugin_plugin_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *InitResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InitResponse) ProtoMessage() {}

func (x *InitResponse) ProtoReflect() protoreflect.Message {
	mi := &file_spire_common_plugin_plugin_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InitResponse.ProtoReflect.Descriptor instead.
func (*InitResponse) Descriptor() ([]byte, []int) {
	return file_spire_common_plugin_plugin_proto_rawDescGZIP(), []int{5}
}

func (x *InitResponse) GetPluginServices() []string {
	if x != nil {
		return x.PluginServices
	}
	return nil
}

// * Global configuration nested type.
type ConfigureRequest_GlobalConfig struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	TrustDomain   string                 `protobuf:"bytes,1,opt,name=trustDomain,proto3" json:"trustDomain,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ConfigureRequest_GlobalConfig) Reset() {
	*x = ConfigureRequest_GlobalConfig{}
	mi := &file_spire_common_plugin_plugin_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ConfigureRequest_GlobalConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigureRequest_GlobalConfig) ProtoMessage() {}

func (x *ConfigureRequest_GlobalConfig) ProtoReflect() protoreflect.Message {
	mi := &file_spire_common_plugin_plugin_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfigureRequest_GlobalConfig.ProtoReflect.Descriptor instead.
func (*ConfigureRequest_GlobalConfig) Descriptor() ([]byte, []int) {
	return file_spire_common_plugin_plugin_proto_rawDescGZIP(), []int{0, 0}
}

func (x *ConfigureRequest_GlobalConfig) GetTrustDomain() string {
	if x != nil {
		return x.TrustDomain
	}
	return ""
}

var File_spire_common_plugin_plugin_proto protoreflect.FileDescriptor

const file_spire_common_plugin_plugin_proto_rawDesc = "" +
	"\n" +
	" spire/common/plugin/plugin.proto\x12\x13spire.common.plugin\"\xc2\x01\n" +
	"\x10ConfigureRequest\x12$\n" +
	"\rconfiguration\x18\x01 \x01(\tR\rconfiguration\x12V\n" +
	"\fglobalConfig\x18\x02 \x01(\v22.spire.common.plugin.ConfigureRequest.GlobalConfigR\fglobalConfig\x1a0\n" +
	"\fGlobalConfig\x12 \n" +
	"\vtrustDomain\x18\x01 \x01(\tR\vtrustDomain\"1\n" +
	"\x11ConfigureResponse\x12\x1c\n" +
	"\terrorList\x18\x01 \x03(\tR\terrorList\"\x16\n" +
	"\x14GetPluginInfoRequest\"\x87\x02\n" +
	"\x15GetPluginInfoResponse\x12\x12\n" +
	"\x04name\x18\x01 \x01(\tR\x04name\x12\x1a\n" +
	"\bcategory\x18\x02 \x01(\tR\bcategory\x12\x12\n" +
	"\x04type\x18\x03 \x01(\tR\x04type\x12 \n" +
	"\vdescription\x18\x04 \x01(\tR\vdescription\x12 \n" +
	"\vdateCreated\x18\x05 \x01(\tR\vdateCreated\x12\x1a\n" +
	"\blocation\x18\x06 \x01(\tR\blocation\x12\x18\n" +
	"\aversion\x18\a \x01(\tR\aversion\x12\x16\n" +
	"\x06author\x18\b \x01(\tR\x06author\x12\x18\n" +
	"\acompany\x18\t \x01(\tR\acompany\"2\n" +
	"\vInitRequest\x12#\n" +
	"\rhost_services\x18\x01 \x03(\tR\fhostServices\"7\n" +
	"\fInitResponse\x12'\n" +
	"\x0fplugin_services\x18\x01 \x03(\tR\x0epluginServices2Y\n" +
	"\n" +
	"PluginInit\x12K\n" +
	"\x04Init\x12 .spire.common.plugin.InitRequest\x1a!.spire.common.plugin.InitResponseB3Z1github.com/spiffe/spire/proto/spire/common/pluginb\x06proto3"

var (
	file_spire_common_plugin_plugin_proto_rawDescOnce sync.Once
	file_spire_common_plugin_plugin_proto_rawDescData []byte
)

func file_spire_common_plugin_plugin_proto_rawDescGZIP() []byte {
	file_spire_common_plugin_plugin_proto_rawDescOnce.Do(func() {
		file_spire_common_plugin_plugin_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_spire_common_plugin_plugin_proto_rawDesc), len(file_spire_common_plugin_plugin_proto_rawDesc)))
	})
	return file_spire_common_plugin_plugin_proto_rawDescData
}

var file_spire_common_plugin_plugin_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_spire_common_plugin_plugin_proto_goTypes = []any{
	(*ConfigureRequest)(nil),              // 0: spire.common.plugin.ConfigureRequest
	(*ConfigureResponse)(nil),             // 1: spire.common.plugin.ConfigureResponse
	(*GetPluginInfoRequest)(nil),          // 2: spire.common.plugin.GetPluginInfoRequest
	(*GetPluginInfoResponse)(nil),         // 3: spire.common.plugin.GetPluginInfoResponse
	(*InitRequest)(nil),                   // 4: spire.common.plugin.InitRequest
	(*InitResponse)(nil),                  // 5: spire.common.plugin.InitResponse
	(*ConfigureRequest_GlobalConfig)(nil), // 6: spire.common.plugin.ConfigureRequest.GlobalConfig
}
var file_spire_common_plugin_plugin_proto_depIdxs = []int32{
	6, // 0: spire.common.plugin.ConfigureRequest.globalConfig:type_name -> spire.common.plugin.ConfigureRequest.GlobalConfig
	4, // 1: spire.common.plugin.PluginInit.Init:input_type -> spire.common.plugin.InitRequest
	5, // 2: spire.common.plugin.PluginInit.Init:output_type -> spire.common.plugin.InitResponse
	2, // [2:3] is the sub-list for method output_type
	1, // [1:2] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_spire_common_plugin_plugin_proto_init() }
func file_spire_common_plugin_plugin_proto_init() {
	if File_spire_common_plugin_plugin_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_spire_common_plugin_plugin_proto_rawDesc), len(file_spire_common_plugin_plugin_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_spire_common_plugin_plugin_proto_goTypes,
		DependencyIndexes: file_spire_common_plugin_plugin_proto_depIdxs,
		MessageInfos:      file_spire_common_plugin_plugin_proto_msgTypes,
	}.Build()
	File_spire_common_plugin_plugin_proto = out.File
	file_spire_common_plugin_plugin_proto_goTypes = nil
	file_spire_common_plugin_plugin_proto_depIdxs = nil
}
