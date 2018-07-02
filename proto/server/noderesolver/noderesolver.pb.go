// Code generated by protoc-gen-go. DO NOT EDIT.
// source: noderesolver.proto

package noderesolver

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import common "github.com/spiffe/spire/proto/common"
import plugin "github.com/spiffe/spire/proto/common/plugin"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// ConfigureRequest from public import github.com/spiffe/spire/proto/common/plugin/plugin.proto
type ConfigureRequest = plugin.ConfigureRequest

// ConfigureResponse from public import github.com/spiffe/spire/proto/common/plugin/plugin.proto
type ConfigureResponse = plugin.ConfigureResponse

// GetPluginInfoRequest from public import github.com/spiffe/spire/proto/common/plugin/plugin.proto
type GetPluginInfoRequest = plugin.GetPluginInfoRequest

// GetPluginInfoResponse from public import github.com/spiffe/spire/proto/common/plugin/plugin.proto
type GetPluginInfoResponse = plugin.GetPluginInfoResponse

// Empty from public import github.com/spiffe/spire/proto/common/common.proto
type Empty = common.Empty

// AttestationData from public import github.com/spiffe/spire/proto/common/common.proto
type AttestationData = common.AttestationData

// Selector from public import github.com/spiffe/spire/proto/common/common.proto
type Selector = common.Selector

// Selectors from public import github.com/spiffe/spire/proto/common/common.proto
type Selectors = common.Selectors

// RegistrationEntry from public import github.com/spiffe/spire/proto/common/common.proto
type RegistrationEntry = common.RegistrationEntry

// RegistrationEntries from public import github.com/spiffe/spire/proto/common/common.proto
type RegistrationEntries = common.RegistrationEntries

// * Represents a request with a list of BaseSPIFFEIDs.
type ResolveRequest struct {
	// * A list of BaseSPIFFE Ids.
	BaseSpiffeIdList     []string `protobuf:"bytes,1,rep,name=baseSpiffeIdList" json:"baseSpiffeIdList,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ResolveRequest) Reset()         { *m = ResolveRequest{} }
func (m *ResolveRequest) String() string { return proto.CompactTextString(m) }
func (*ResolveRequest) ProtoMessage()    {}
func (*ResolveRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_noderesolver_627a9baa5d375c85, []int{0}
}
func (m *ResolveRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ResolveRequest.Unmarshal(m, b)
}
func (m *ResolveRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ResolveRequest.Marshal(b, m, deterministic)
}
func (dst *ResolveRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ResolveRequest.Merge(dst, src)
}
func (m *ResolveRequest) XXX_Size() int {
	return xxx_messageInfo_ResolveRequest.Size(m)
}
func (m *ResolveRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ResolveRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ResolveRequest proto.InternalMessageInfo

func (m *ResolveRequest) GetBaseSpiffeIdList() []string {
	if m != nil {
		return m.BaseSpiffeIdList
	}
	return nil
}

// * Represents a response with a map of SPIFFE ID to a list of Selectors.
type ResolveResponse struct {
	// * Map[SPIFFE_ID] => Selectors.
	Map                  map[string]*common.Selectors `protobuf:"bytes,1,rep,name=map" json:"map,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	XXX_NoUnkeyedLiteral struct{}                     `json:"-"`
	XXX_unrecognized     []byte                       `json:"-"`
	XXX_sizecache        int32                        `json:"-"`
}

func (m *ResolveResponse) Reset()         { *m = ResolveResponse{} }
func (m *ResolveResponse) String() string { return proto.CompactTextString(m) }
func (*ResolveResponse) ProtoMessage()    {}
func (*ResolveResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_noderesolver_627a9baa5d375c85, []int{1}
}
func (m *ResolveResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ResolveResponse.Unmarshal(m, b)
}
func (m *ResolveResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ResolveResponse.Marshal(b, m, deterministic)
}
func (dst *ResolveResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ResolveResponse.Merge(dst, src)
}
func (m *ResolveResponse) XXX_Size() int {
	return xxx_messageInfo_ResolveResponse.Size(m)
}
func (m *ResolveResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ResolveResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ResolveResponse proto.InternalMessageInfo

func (m *ResolveResponse) GetMap() map[string]*common.Selectors {
	if m != nil {
		return m.Map
	}
	return nil
}

func init() {
	proto.RegisterType((*ResolveRequest)(nil), "spire.server.noderesolver.ResolveRequest")
	proto.RegisterType((*ResolveResponse)(nil), "spire.server.noderesolver.ResolveResponse")
	proto.RegisterMapType((map[string]*common.Selectors)(nil), "spire.server.noderesolver.ResolveResponse.MapEntry")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for NodeResolver service

type NodeResolverClient interface {
	// * Retrieves a list of properties reflecting the current state of a particular node(s).
	Resolve(ctx context.Context, in *ResolveRequest, opts ...grpc.CallOption) (*ResolveResponse, error)
	// * Responsible for configuration of the plugin.
	Configure(ctx context.Context, in *plugin.ConfigureRequest, opts ...grpc.CallOption) (*plugin.ConfigureResponse, error)
	// * Returns the  version and related metadata of the installed plugin.
	GetPluginInfo(ctx context.Context, in *plugin.GetPluginInfoRequest, opts ...grpc.CallOption) (*plugin.GetPluginInfoResponse, error)
}

type nodeResolverClient struct {
	cc *grpc.ClientConn
}

func NewNodeResolverClient(cc *grpc.ClientConn) NodeResolverClient {
	return &nodeResolverClient{cc}
}

func (c *nodeResolverClient) Resolve(ctx context.Context, in *ResolveRequest, opts ...grpc.CallOption) (*ResolveResponse, error) {
	out := new(ResolveResponse)
	err := grpc.Invoke(ctx, "/spire.server.noderesolver.NodeResolver/Resolve", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *nodeResolverClient) Configure(ctx context.Context, in *plugin.ConfigureRequest, opts ...grpc.CallOption) (*plugin.ConfigureResponse, error) {
	out := new(plugin.ConfigureResponse)
	err := grpc.Invoke(ctx, "/spire.server.noderesolver.NodeResolver/Configure", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *nodeResolverClient) GetPluginInfo(ctx context.Context, in *plugin.GetPluginInfoRequest, opts ...grpc.CallOption) (*plugin.GetPluginInfoResponse, error) {
	out := new(plugin.GetPluginInfoResponse)
	err := grpc.Invoke(ctx, "/spire.server.noderesolver.NodeResolver/GetPluginInfo", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for NodeResolver service

type NodeResolverServer interface {
	// * Retrieves a list of properties reflecting the current state of a particular node(s).
	Resolve(context.Context, *ResolveRequest) (*ResolveResponse, error)
	// * Responsible for configuration of the plugin.
	Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error)
	// * Returns the  version and related metadata of the installed plugin.
	GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error)
}

func RegisterNodeResolverServer(s *grpc.Server, srv NodeResolverServer) {
	s.RegisterService(&_NodeResolver_serviceDesc, srv)
}

func _NodeResolver_Resolve_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ResolveRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NodeResolverServer).Resolve(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/spire.server.noderesolver.NodeResolver/Resolve",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NodeResolverServer).Resolve(ctx, req.(*ResolveRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NodeResolver_Configure_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(plugin.ConfigureRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NodeResolverServer).Configure(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/spire.server.noderesolver.NodeResolver/Configure",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NodeResolverServer).Configure(ctx, req.(*plugin.ConfigureRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NodeResolver_GetPluginInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(plugin.GetPluginInfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NodeResolverServer).GetPluginInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/spire.server.noderesolver.NodeResolver/GetPluginInfo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NodeResolverServer).GetPluginInfo(ctx, req.(*plugin.GetPluginInfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _NodeResolver_serviceDesc = grpc.ServiceDesc{
	ServiceName: "spire.server.noderesolver.NodeResolver",
	HandlerType: (*NodeResolverServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Resolve",
			Handler:    _NodeResolver_Resolve_Handler,
		},
		{
			MethodName: "Configure",
			Handler:    _NodeResolver_Configure_Handler,
		},
		{
			MethodName: "GetPluginInfo",
			Handler:    _NodeResolver_GetPluginInfo_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "noderesolver.proto",
}

func init() { proto.RegisterFile("noderesolver.proto", fileDescriptor_noderesolver_627a9baa5d375c85) }

var fileDescriptor_noderesolver_627a9baa5d375c85 = []byte{
	// 342 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x92, 0x4f, 0x4f, 0xc2, 0x40,
	0x10, 0xc5, 0x5d, 0x88, 0x7f, 0x18, 0x10, 0xc9, 0x5e, 0xc4, 0x9e, 0x08, 0x89, 0x06, 0x49, 0x6c,
	0x23, 0x5c, 0x88, 0xf1, 0xa4, 0x21, 0x86, 0xc4, 0x3f, 0xa4, 0xdc, 0x38, 0x59, 0x60, 0x8a, 0x8d,
	0x6d, 0x67, 0xdd, 0xdd, 0x92, 0xf0, 0x91, 0xbc, 0xfb, 0x01, 0x0d, 0xdb, 0x42, 0x00, 0xa3, 0x72,
	0xda, 0xcd, 0xcc, 0xfb, 0xcd, 0x9b, 0xd7, 0x2e, 0xf0, 0x98, 0x26, 0x28, 0x51, 0x51, 0x38, 0x43,
	0x69, 0x0b, 0x49, 0x9a, 0xf8, 0x99, 0x12, 0x81, 0x44, 0x5b, 0xa1, 0x5c, 0xd4, 0xd6, 0x05, 0x56,
	0x67, 0x1a, 0xe8, 0xb7, 0x64, 0x64, 0x8f, 0x29, 0x72, 0x94, 0x08, 0x7c, 0x1f, 0x1d, 0x23, 0x76,
	0x0c, 0xe9, 0x8c, 0x29, 0x8a, 0x28, 0x76, 0x44, 0x98, 0x4c, 0x83, 0xe5, 0x91, 0x0e, 0xb5, 0xae,
	0x77, 0x22, 0xd3, 0x23, 0x45, 0xea, 0xb7, 0x50, 0x76, 0x53, 0x63, 0x17, 0x3f, 0x12, 0x54, 0x9a,
	0x37, 0xa1, 0x32, 0xf2, 0x14, 0x0e, 0x0c, 0xdf, 0x9b, 0x3c, 0x06, 0x4a, 0x57, 0x59, 0x2d, 0xdf,
	0x28, 0xb8, 0x3f, 0xea, 0xf5, 0x4f, 0x06, 0x27, 0x2b, 0x5c, 0x09, 0x8a, 0x15, 0xf2, 0x2e, 0xe4,
	0x23, 0x4f, 0x18, 0xa4, 0xd8, 0x6a, 0xdb, 0xbf, 0xe6, 0xb4, 0xb7, 0x40, 0xfb, 0xc9, 0x13, 0xdd,
	0x58, 0xcb, 0xb9, 0xbb, 0xe0, 0xad, 0x17, 0x38, 0x5a, 0x16, 0x78, 0x05, 0xf2, 0xef, 0x38, 0xaf,
	0xb2, 0x1a, 0x6b, 0x14, 0xdc, 0xc5, 0x95, 0x5f, 0xc1, 0xfe, 0xcc, 0x0b, 0x13, 0xac, 0xe6, 0x6a,
	0xac, 0x51, 0x6c, 0x9d, 0x66, 0x36, 0x59, 0xb4, 0x01, 0x86, 0x38, 0xd6, 0x24, 0x95, 0x9b, 0xaa,
	0x6e, 0x72, 0x1d, 0xd6, 0xfa, 0xca, 0x41, 0xe9, 0x99, 0x26, 0x98, 0xd9, 0x4a, 0xfe, 0x0a, 0x87,
	0xd9, 0x9d, 0x5f, 0xee, 0xb2, 0xa6, 0xf9, 0x3c, 0x56, 0x73, 0xf7, 0x44, 0x7c, 0x08, 0x85, 0x7b,
	0x8a, 0xfd, 0x60, 0x9a, 0x48, 0xe4, 0xe7, 0x9b, 0x3b, 0x66, 0x3f, 0x6e, 0xd5, 0x5f, 0xce, 0xbf,
	0xf8, 0x4f, 0x96, 0xcd, 0xf6, 0xe1, 0xf8, 0x01, 0x75, 0xdf, 0xb4, 0x7b, 0xb1, 0x4f, 0xab, 0x0c,
	0x9b, 0xe0, 0x86, 0x66, 0x3b, 0xc3, 0x9f, 0xd2, 0xd4, 0xe7, 0xae, 0x3c, 0x2c, 0xad, 0x67, 0xec,
	0xef, 0xf5, 0xd9, 0xe8, 0xc0, 0xbc, 0x9d, 0xf6, 0x77, 0x00, 0x00, 0x00, 0xff, 0xff, 0x4e, 0x9d,
	0x91, 0xc3, 0xd9, 0x02, 0x00, 0x00,
}
