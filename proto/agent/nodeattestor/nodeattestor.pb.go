// Code generated by protoc-gen-go. DO NOT EDIT.
// source: proto/agent/nodeattestor/nodeattestor.proto

package nodeattestor // import "github.com/spiffe/spire/proto/agent/nodeattestor"

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

// Empty from public import proto/common/common.proto
type Empty = common.Empty

// AttestationData from public import proto/common/common.proto
type AttestationData = common.AttestationData

// Selector from public import proto/common/common.proto
type Selector = common.Selector

// Selectors from public import proto/common/common.proto
type Selectors = common.Selectors

// RegistrationEntry from public import proto/common/common.proto
type RegistrationEntry = common.RegistrationEntry

// RegistrationEntries from public import proto/common/common.proto
type RegistrationEntries = common.RegistrationEntries

// Certificate from public import proto/common/common.proto
type Certificate = common.Certificate

// PublicKey from public import proto/common/common.proto
type PublicKey = common.PublicKey

// Bundle from public import proto/common/common.proto
type Bundle = common.Bundle

// ConfigureRequest from public import proto/common/plugin/plugin.proto
type ConfigureRequest = plugin.ConfigureRequest

// GlobalConfig from public import proto/common/plugin/plugin.proto
type ConfigureRequest_GlobalConfig = plugin.ConfigureRequest_GlobalConfig

// ConfigureResponse from public import proto/common/plugin/plugin.proto
type ConfigureResponse = plugin.ConfigureResponse

// GetPluginInfoRequest from public import proto/common/plugin/plugin.proto
type GetPluginInfoRequest = plugin.GetPluginInfoRequest

// GetPluginInfoResponse from public import proto/common/plugin/plugin.proto
type GetPluginInfoResponse = plugin.GetPluginInfoResponse

// * Represents an empty request
type FetchAttestationDataRequest struct {
	Challenge            []byte   `protobuf:"bytes,1,opt,name=challenge,proto3" json:"challenge,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *FetchAttestationDataRequest) Reset()         { *m = FetchAttestationDataRequest{} }
func (m *FetchAttestationDataRequest) String() string { return proto.CompactTextString(m) }
func (*FetchAttestationDataRequest) ProtoMessage()    {}
func (*FetchAttestationDataRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_nodeattestor_ba24e02660f00088, []int{0}
}
func (m *FetchAttestationDataRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FetchAttestationDataRequest.Unmarshal(m, b)
}
func (m *FetchAttestationDataRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FetchAttestationDataRequest.Marshal(b, m, deterministic)
}
func (dst *FetchAttestationDataRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FetchAttestationDataRequest.Merge(dst, src)
}
func (m *FetchAttestationDataRequest) XXX_Size() int {
	return xxx_messageInfo_FetchAttestationDataRequest.Size(m)
}
func (m *FetchAttestationDataRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_FetchAttestationDataRequest.DiscardUnknown(m)
}

var xxx_messageInfo_FetchAttestationDataRequest proto.InternalMessageInfo

func (m *FetchAttestationDataRequest) GetChallenge() []byte {
	if m != nil {
		return m.Challenge
	}
	return nil
}

// * Represents the attested data and base SPIFFE ID
type FetchAttestationDataResponse struct {
	// * A type which contains attestation data for specific platform
	AttestationData *common.AttestationData `protobuf:"bytes,1,opt,name=attestationData,proto3" json:"attestationData,omitempty"`
	// * SPIFFE ID
	SpiffeId string `protobuf:"bytes,2,opt,name=spiffeId,proto3" json:"spiffeId,omitempty"`
	// * response to the challenge (if challenge was present) *
	Response             []byte   `protobuf:"bytes,3,opt,name=response,proto3" json:"response,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *FetchAttestationDataResponse) Reset()         { *m = FetchAttestationDataResponse{} }
func (m *FetchAttestationDataResponse) String() string { return proto.CompactTextString(m) }
func (*FetchAttestationDataResponse) ProtoMessage()    {}
func (*FetchAttestationDataResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_nodeattestor_ba24e02660f00088, []int{1}
}
func (m *FetchAttestationDataResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FetchAttestationDataResponse.Unmarshal(m, b)
}
func (m *FetchAttestationDataResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FetchAttestationDataResponse.Marshal(b, m, deterministic)
}
func (dst *FetchAttestationDataResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FetchAttestationDataResponse.Merge(dst, src)
}
func (m *FetchAttestationDataResponse) XXX_Size() int {
	return xxx_messageInfo_FetchAttestationDataResponse.Size(m)
}
func (m *FetchAttestationDataResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_FetchAttestationDataResponse.DiscardUnknown(m)
}

var xxx_messageInfo_FetchAttestationDataResponse proto.InternalMessageInfo

func (m *FetchAttestationDataResponse) GetAttestationData() *common.AttestationData {
	if m != nil {
		return m.AttestationData
	}
	return nil
}

func (m *FetchAttestationDataResponse) GetSpiffeId() string {
	if m != nil {
		return m.SpiffeId
	}
	return ""
}

func (m *FetchAttestationDataResponse) GetResponse() []byte {
	if m != nil {
		return m.Response
	}
	return nil
}

func init() {
	proto.RegisterType((*FetchAttestationDataRequest)(nil), "spire.agent.nodeattestor.FetchAttestationDataRequest")
	proto.RegisterType((*FetchAttestationDataResponse)(nil), "spire.agent.nodeattestor.FetchAttestationDataResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// NodeAttestorClient is the client API for NodeAttestor service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type NodeAttestorClient interface {
	// * Returns the node attestation data for specific platform and the generated Base SPIFFE ID for CSR formation
	FetchAttestationData(ctx context.Context, opts ...grpc.CallOption) (NodeAttestor_FetchAttestationDataClient, error)
	// * Applies the plugin configuration and returns configuration errors
	Configure(ctx context.Context, in *plugin.ConfigureRequest, opts ...grpc.CallOption) (*plugin.ConfigureResponse, error)
	// * Returns the version and related metadata of the plugin
	GetPluginInfo(ctx context.Context, in *plugin.GetPluginInfoRequest, opts ...grpc.CallOption) (*plugin.GetPluginInfoResponse, error)
}

type nodeAttestorClient struct {
	cc *grpc.ClientConn
}

func NewNodeAttestorClient(cc *grpc.ClientConn) NodeAttestorClient {
	return &nodeAttestorClient{cc}
}

func (c *nodeAttestorClient) FetchAttestationData(ctx context.Context, opts ...grpc.CallOption) (NodeAttestor_FetchAttestationDataClient, error) {
	stream, err := c.cc.NewStream(ctx, &_NodeAttestor_serviceDesc.Streams[0], "/spire.agent.nodeattestor.NodeAttestor/FetchAttestationData", opts...)
	if err != nil {
		return nil, err
	}
	x := &nodeAttestorFetchAttestationDataClient{stream}
	return x, nil
}

type NodeAttestor_FetchAttestationDataClient interface {
	Send(*FetchAttestationDataRequest) error
	Recv() (*FetchAttestationDataResponse, error)
	grpc.ClientStream
}

type nodeAttestorFetchAttestationDataClient struct {
	grpc.ClientStream
}

func (x *nodeAttestorFetchAttestationDataClient) Send(m *FetchAttestationDataRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *nodeAttestorFetchAttestationDataClient) Recv() (*FetchAttestationDataResponse, error) {
	m := new(FetchAttestationDataResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *nodeAttestorClient) Configure(ctx context.Context, in *plugin.ConfigureRequest, opts ...grpc.CallOption) (*plugin.ConfigureResponse, error) {
	out := new(plugin.ConfigureResponse)
	err := c.cc.Invoke(ctx, "/spire.agent.nodeattestor.NodeAttestor/Configure", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *nodeAttestorClient) GetPluginInfo(ctx context.Context, in *plugin.GetPluginInfoRequest, opts ...grpc.CallOption) (*plugin.GetPluginInfoResponse, error) {
	out := new(plugin.GetPluginInfoResponse)
	err := c.cc.Invoke(ctx, "/spire.agent.nodeattestor.NodeAttestor/GetPluginInfo", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// NodeAttestorServer is the server API for NodeAttestor service.
type NodeAttestorServer interface {
	// * Returns the node attestation data for specific platform and the generated Base SPIFFE ID for CSR formation
	FetchAttestationData(NodeAttestor_FetchAttestationDataServer) error
	// * Applies the plugin configuration and returns configuration errors
	Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error)
	// * Returns the version and related metadata of the plugin
	GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error)
}

func RegisterNodeAttestorServer(s *grpc.Server, srv NodeAttestorServer) {
	s.RegisterService(&_NodeAttestor_serviceDesc, srv)
}

func _NodeAttestor_FetchAttestationData_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(NodeAttestorServer).FetchAttestationData(&nodeAttestorFetchAttestationDataServer{stream})
}

type NodeAttestor_FetchAttestationDataServer interface {
	Send(*FetchAttestationDataResponse) error
	Recv() (*FetchAttestationDataRequest, error)
	grpc.ServerStream
}

type nodeAttestorFetchAttestationDataServer struct {
	grpc.ServerStream
}

func (x *nodeAttestorFetchAttestationDataServer) Send(m *FetchAttestationDataResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *nodeAttestorFetchAttestationDataServer) Recv() (*FetchAttestationDataRequest, error) {
	m := new(FetchAttestationDataRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _NodeAttestor_Configure_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(plugin.ConfigureRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NodeAttestorServer).Configure(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/spire.agent.nodeattestor.NodeAttestor/Configure",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NodeAttestorServer).Configure(ctx, req.(*plugin.ConfigureRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NodeAttestor_GetPluginInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(plugin.GetPluginInfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NodeAttestorServer).GetPluginInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/spire.agent.nodeattestor.NodeAttestor/GetPluginInfo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NodeAttestorServer).GetPluginInfo(ctx, req.(*plugin.GetPluginInfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _NodeAttestor_serviceDesc = grpc.ServiceDesc{
	ServiceName: "spire.agent.nodeattestor.NodeAttestor",
	HandlerType: (*NodeAttestorServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Configure",
			Handler:    _NodeAttestor_Configure_Handler,
		},
		{
			MethodName: "GetPluginInfo",
			Handler:    _NodeAttestor_GetPluginInfo_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "FetchAttestationData",
			Handler:       _NodeAttestor_FetchAttestationData_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "proto/agent/nodeattestor/nodeattestor.proto",
}

func init() {
	proto.RegisterFile("proto/agent/nodeattestor/nodeattestor.proto", fileDescriptor_nodeattestor_ba24e02660f00088)
}

var fileDescriptor_nodeattestor_ba24e02660f00088 = []byte{
	// 331 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x52, 0xdd, 0x4a, 0xc3, 0x30,
	0x18, 0x35, 0x13, 0xc4, 0xc5, 0x89, 0x10, 0xbc, 0xa8, 0x75, 0xc2, 0x18, 0x28, 0x53, 0x21, 0x1d,
	0x13, 0xbd, 0xf1, 0x6a, 0x2a, 0x8e, 0xdd, 0xc8, 0xd8, 0xe5, 0xee, 0xb2, 0xed, 0x6b, 0x1b, 0xe8,
	0x92, 0xda, 0xa4, 0x0f, 0xe1, 0x53, 0xf8, 0x66, 0x3e, 0x8b, 0x2c, 0x49, 0xab, 0x1d, 0x9d, 0x3f,
	0x57, 0xe1, 0xeb, 0x39, 0xe7, 0x3b, 0xa7, 0x27, 0xc1, 0xd7, 0x69, 0x26, 0xb5, 0x0c, 0x58, 0x04,
	0x42, 0x07, 0x42, 0x2e, 0x81, 0x69, 0x0d, 0x4a, 0xcb, 0xac, 0x32, 0x50, 0xc3, 0x22, 0x9e, 0x4a,
	0x79, 0x06, 0xd4, 0x90, 0xe9, 0x77, 0xdc, 0x3f, 0xb1, 0x6b, 0x16, 0x72, 0xb5, 0x92, 0xc2, 0x1d,
	0x56, 0xe4, 0x77, 0x2a, 0x50, 0x9a, 0xe4, 0x11, 0x2f, 0x0e, 0xcb, 0xe8, 0xde, 0xe3, 0xd3, 0x67,
	0xd0, 0x8b, 0x78, 0x68, 0xb6, 0x31, 0xcd, 0xa5, 0x78, 0x62, 0x9a, 0x4d, 0xe1, 0x35, 0x07, 0xa5,
	0x49, 0x1b, 0x37, 0x17, 0x31, 0x4b, 0x12, 0x10, 0x11, 0x78, 0xa8, 0x83, 0x7a, 0xad, 0xe9, 0xd7,
	0x87, 0xee, 0x3b, 0xc2, 0xed, 0x7a, 0xb5, 0x4a, 0xa5, 0x50, 0x40, 0x46, 0xf8, 0x88, 0x55, 0x21,
	0xb3, 0xe4, 0x60, 0x70, 0x46, 0xed, 0xef, 0xb8, 0xb4, 0x9b, 0xfa, 0x4d, 0x15, 0xf1, 0xf1, 0xbe,
	0x4a, 0x79, 0x18, 0xc2, 0x78, 0xe9, 0x35, 0x3a, 0xa8, 0xd7, 0x9c, 0x96, 0xf3, 0x1a, 0xcb, 0x9c,
	0xa1, 0xb7, 0x6b, 0x22, 0x96, 0xf3, 0xe0, 0xa3, 0x81, 0x5b, 0x2f, 0x72, 0x09, 0x43, 0x57, 0x16,
	0x79, 0x43, 0xf8, 0xb8, 0x2e, 0x32, 0xb9, 0xa5, 0xdb, 0x0a, 0xa6, 0x3f, 0x14, 0xe4, 0xdf, 0xfd,
	0x57, 0x66, 0x83, 0xf5, 0x50, 0x1f, 0x91, 0x19, 0x6e, 0x3e, 0x4a, 0x11, 0xf2, 0x28, 0xcf, 0x80,
	0x9c, 0x57, 0x1b, 0x71, 0x97, 0x54, 0xe2, 0x85, 0xdf, 0xc5, 0x6f, 0x34, 0xd7, 0x7c, 0x88, 0x0f,
	0x47, 0xa0, 0x27, 0x06, 0x1e, 0x8b, 0x50, 0x92, 0xcb, 0x5a, 0x61, 0x85, 0x53, 0x78, 0x5c, 0xfd,
	0x85, 0x6a, 0x7d, 0x1e, 0x06, 0xb3, 0x7e, 0xc4, 0x75, 0x9c, 0xcf, 0xd7, 0xec, 0xc0, 0xde, 0x49,
	0x60, 0xe4, 0xc1, 0xb6, 0xd7, 0x3d, 0xd9, 0x99, 0xa0, 0xf9, 0x9e, 0x41, 0x6f, 0x3e, 0x03, 0x00,
	0x00, 0xff, 0xff, 0x81, 0x0c, 0x31, 0x10, 0x04, 0x03, 0x00, 0x00,
}
