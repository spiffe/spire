//* Environment specific plugin to attest a workloads “selector”
//data. a

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.14.0
// source: spire/agent/workloadattestor/workloadattestor.proto

package workloadattestor

import (
	common "github.com/spiffe/spire/proto/spire/common"
	plugin "github.com/spiffe/spire/proto/spire/common/plugin"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

//* Represents the workload PID.
type AttestRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//* Workload PID
	Pid int32 `protobuf:"varint,1,opt,name=pid,proto3" json:"pid,omitempty"`
}

func (x *AttestRequest) Reset() {
	*x = AttestRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_spire_agent_workloadattestor_workloadattestor_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AttestRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AttestRequest) ProtoMessage() {}

func (x *AttestRequest) ProtoReflect() protoreflect.Message {
	mi := &file_spire_agent_workloadattestor_workloadattestor_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AttestRequest.ProtoReflect.Descriptor instead.
func (*AttestRequest) Descriptor() ([]byte, []int) {
	return file_spire_agent_workloadattestor_workloadattestor_proto_rawDescGZIP(), []int{0}
}

func (x *AttestRequest) GetPid() int32 {
	if x != nil {
		return x.Pid
	}
	return 0
}

//* Represents a list of selectors resolved for a given PID.
type AttestResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//* List of selectors
	Selectors []*common.Selector `protobuf:"bytes,1,rep,name=selectors,proto3" json:"selectors,omitempty"`
}

func (x *AttestResponse) Reset() {
	*x = AttestResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_spire_agent_workloadattestor_workloadattestor_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AttestResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AttestResponse) ProtoMessage() {}

func (x *AttestResponse) ProtoReflect() protoreflect.Message {
	mi := &file_spire_agent_workloadattestor_workloadattestor_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AttestResponse.ProtoReflect.Descriptor instead.
func (*AttestResponse) Descriptor() ([]byte, []int) {
	return file_spire_agent_workloadattestor_workloadattestor_proto_rawDescGZIP(), []int{1}
}

func (x *AttestResponse) GetSelectors() []*common.Selector {
	if x != nil {
		return x.Selectors
	}
	return nil
}

var File_spire_agent_workloadattestor_workloadattestor_proto protoreflect.FileDescriptor

var file_spire_agent_workloadattestor_workloadattestor_proto_rawDesc = []byte{
	0x0a, 0x33, 0x73, 0x70, 0x69, 0x72, 0x65, 0x2f, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2f, 0x77, 0x6f,
	0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x6f, 0x72, 0x2f, 0x77,
	0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x6f, 0x72, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1c, 0x73, 0x70, 0x69, 0x72, 0x65, 0x2e, 0x61, 0x67, 0x65,
	0x6e, 0x74, 0x2e, 0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x61, 0x74, 0x74, 0x65, 0x73,
	0x74, 0x6f, 0x72, 0x1a, 0x19, 0x73, 0x70, 0x69, 0x72, 0x65, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f,
	0x6e, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x20,
	0x73, 0x70, 0x69, 0x72, 0x65, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x70, 0x6c, 0x75,
	0x67, 0x69, 0x6e, 0x2f, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0x21, 0x0a, 0x0d, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x10, 0x0a, 0x03, 0x70, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x03,
	0x70, 0x69, 0x64, 0x22, 0x46, 0x0a, 0x0e, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x34, 0x0a, 0x09, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f,
	0x72, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x73, 0x70, 0x69, 0x72, 0x65,
	0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72,
	0x52, 0x09, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x73, 0x32, 0xbb, 0x02, 0x0a, 0x10,
	0x57, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x6f, 0x72,
	0x12, 0x63, 0x0a, 0x06, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x12, 0x2b, 0x2e, 0x73, 0x70, 0x69,
	0x72, 0x65, 0x2e, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e, 0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61,
	0x64, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x6f, 0x72, 0x2e, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2c, 0x2e, 0x73, 0x70, 0x69, 0x72, 0x65, 0x2e,
	0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e, 0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x61, 0x74,
	0x74, 0x65, 0x73, 0x74, 0x6f, 0x72, 0x2e, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x5a, 0x0a, 0x09, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75,
	0x72, 0x65, 0x12, 0x25, 0x2e, 0x73, 0x70, 0x69, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f,
	0x6e, 0x2e, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75,
	0x72, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x26, 0x2e, 0x73, 0x70, 0x69, 0x72,
	0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x2e,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x66, 0x0a, 0x0d, 0x47, 0x65, 0x74, 0x50, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x49, 0x6e,
	0x66, 0x6f, 0x12, 0x29, 0x2e, 0x73, 0x70, 0x69, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f,
	0x6e, 0x2e, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x2e, 0x47, 0x65, 0x74, 0x50, 0x6c, 0x75, 0x67,
	0x69, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2a, 0x2e,
	0x73, 0x70, 0x69, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x6c, 0x75,
	0x67, 0x69, 0x6e, 0x2e, 0x47, 0x65, 0x74, 0x50, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x49, 0x6e, 0x66,
	0x6f, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x3c, 0x5a, 0x3a, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x70, 0x69, 0x66, 0x66, 0x65, 0x2f, 0x73,
	0x70, 0x69, 0x72, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x70, 0x69, 0x72, 0x65,
	0x2f, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2f, 0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x61,
	0x74, 0x74, 0x65, 0x73, 0x74, 0x6f, 0x72, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_spire_agent_workloadattestor_workloadattestor_proto_rawDescOnce sync.Once
	file_spire_agent_workloadattestor_workloadattestor_proto_rawDescData = file_spire_agent_workloadattestor_workloadattestor_proto_rawDesc
)

func file_spire_agent_workloadattestor_workloadattestor_proto_rawDescGZIP() []byte {
	file_spire_agent_workloadattestor_workloadattestor_proto_rawDescOnce.Do(func() {
		file_spire_agent_workloadattestor_workloadattestor_proto_rawDescData = protoimpl.X.CompressGZIP(file_spire_agent_workloadattestor_workloadattestor_proto_rawDescData)
	})
	return file_spire_agent_workloadattestor_workloadattestor_proto_rawDescData
}

var file_spire_agent_workloadattestor_workloadattestor_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_spire_agent_workloadattestor_workloadattestor_proto_goTypes = []interface{}{
	(*AttestRequest)(nil),                // 0: spire.agent.workloadattestor.AttestRequest
	(*AttestResponse)(nil),               // 1: spire.agent.workloadattestor.AttestResponse
	(*common.Selector)(nil),              // 2: spire.common.Selector
	(*plugin.ConfigureRequest)(nil),      // 3: spire.common.plugin.ConfigureRequest
	(*plugin.GetPluginInfoRequest)(nil),  // 4: spire.common.plugin.GetPluginInfoRequest
	(*plugin.ConfigureResponse)(nil),     // 5: spire.common.plugin.ConfigureResponse
	(*plugin.GetPluginInfoResponse)(nil), // 6: spire.common.plugin.GetPluginInfoResponse
}
var file_spire_agent_workloadattestor_workloadattestor_proto_depIdxs = []int32{
	2, // 0: spire.agent.workloadattestor.AttestResponse.selectors:type_name -> spire.common.Selector
	0, // 1: spire.agent.workloadattestor.WorkloadAttestor.Attest:input_type -> spire.agent.workloadattestor.AttestRequest
	3, // 2: spire.agent.workloadattestor.WorkloadAttestor.Configure:input_type -> spire.common.plugin.ConfigureRequest
	4, // 3: spire.agent.workloadattestor.WorkloadAttestor.GetPluginInfo:input_type -> spire.common.plugin.GetPluginInfoRequest
	1, // 4: spire.agent.workloadattestor.WorkloadAttestor.Attest:output_type -> spire.agent.workloadattestor.AttestResponse
	5, // 5: spire.agent.workloadattestor.WorkloadAttestor.Configure:output_type -> spire.common.plugin.ConfigureResponse
	6, // 6: spire.agent.workloadattestor.WorkloadAttestor.GetPluginInfo:output_type -> spire.common.plugin.GetPluginInfoResponse
	4, // [4:7] is the sub-list for method output_type
	1, // [1:4] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_spire_agent_workloadattestor_workloadattestor_proto_init() }
func file_spire_agent_workloadattestor_workloadattestor_proto_init() {
	if File_spire_agent_workloadattestor_workloadattestor_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_spire_agent_workloadattestor_workloadattestor_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AttestRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_spire_agent_workloadattestor_workloadattestor_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AttestResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_spire_agent_workloadattestor_workloadattestor_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_spire_agent_workloadattestor_workloadattestor_proto_goTypes,
		DependencyIndexes: file_spire_agent_workloadattestor_workloadattestor_proto_depIdxs,
		MessageInfos:      file_spire_agent_workloadattestor_workloadattestor_proto_msgTypes,
	}.Build()
	File_spire_agent_workloadattestor_workloadattestor_proto = out.File
	file_spire_agent_workloadattestor_workloadattestor_proto_rawDesc = nil
	file_spire_agent_workloadattestor_workloadattestor_proto_goTypes = nil
	file_spire_agent_workloadattestor_workloadattestor_proto_depIdxs = nil
}
