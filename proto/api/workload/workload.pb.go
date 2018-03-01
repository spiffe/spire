// Code generated by protoc-gen-go. DO NOT EDIT.
// source: workload.proto

/*
Package workload is a generated protocol buffer package.

It is generated from these files:
	workload.proto

It has these top-level messages:
	X509SVIDRequest
	X509SVIDResponse
	X509SVID
*/
package workload

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

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

type X509SVIDRequest struct {
}

func (m *X509SVIDRequest) Reset()                    { *m = X509SVIDRequest{} }
func (m *X509SVIDRequest) String() string            { return proto.CompactTextString(m) }
func (*X509SVIDRequest) ProtoMessage()               {}
func (*X509SVIDRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

// The X509SVIDResponse message carries a set of X.509 SVIDs and their
// associated information. It also carries a set of global CRLs, and a
// TTL to inform the workload when it should check back next.
type X509SVIDResponse struct {
	// A list of X509SVID messages, each of which includes a single
	// SPIFFE Verifiable Identity Document, along with its private key
	// and bundle.
	Svids []*X509SVID `protobuf:"bytes,1,rep,name=svids" json:"svids,omitempty"`
	// ASN.1 DER encoded
	Crl [][]byte `protobuf:"bytes,2,rep,name=crl,proto3" json:"crl,omitempty"`
	// CA certificate bundles belonging to foreign Trust Domains that the
	// workload should trust, keyed by the SPIFFE ID of the foreign
	// domain. Bundles are ASN.1 DER encoded.
	FederatedBundles map[string][]byte `protobuf:"bytes,3,rep,name=federated_bundles,json=federatedBundles" json:"federated_bundles,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (m *X509SVIDResponse) Reset()                    { *m = X509SVIDResponse{} }
func (m *X509SVIDResponse) String() string            { return proto.CompactTextString(m) }
func (*X509SVIDResponse) ProtoMessage()               {}
func (*X509SVIDResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *X509SVIDResponse) GetSvids() []*X509SVID {
	if m != nil {
		return m.Svids
	}
	return nil
}

func (m *X509SVIDResponse) GetCrl() [][]byte {
	if m != nil {
		return m.Crl
	}
	return nil
}

func (m *X509SVIDResponse) GetFederatedBundles() map[string][]byte {
	if m != nil {
		return m.FederatedBundles
	}
	return nil
}

// The X509SVID message carries a single SVID and all associated
// information, including CA bundles.
type X509SVID struct {
	// The SPIFFE ID of the SVID in this entry
	SpiffeId string `protobuf:"bytes,1,opt,name=spiffe_id,json=spiffeId" json:"spiffe_id,omitempty"`
	// ASN.1 DER encoded certificate chain. MAY include intermediates,
	// the leaf certificate (or SVID itself) MUST come first.
	X509Svid []byte `protobuf:"bytes,2,opt,name=x509_svid,json=x509Svid,proto3" json:"x509_svid,omitempty"`
	// ASN.1 DER encoded PKCS#8 private key. MUST be unencrypted.
	X509SvidKey []byte `protobuf:"bytes,3,opt,name=x509_svid_key,json=x509SvidKey,proto3" json:"x509_svid_key,omitempty"`
	// CA certificates belonging to the Trust Domain
	// ASN.1 DER encoded
	Bundle []byte `protobuf:"bytes,4,opt,name=bundle,proto3" json:"bundle,omitempty"`
}

func (m *X509SVID) Reset()                    { *m = X509SVID{} }
func (m *X509SVID) String() string            { return proto.CompactTextString(m) }
func (*X509SVID) ProtoMessage()               {}
func (*X509SVID) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *X509SVID) GetSpiffeId() string {
	if m != nil {
		return m.SpiffeId
	}
	return ""
}

func (m *X509SVID) GetX509Svid() []byte {
	if m != nil {
		return m.X509Svid
	}
	return nil
}

func (m *X509SVID) GetX509SvidKey() []byte {
	if m != nil {
		return m.X509SvidKey
	}
	return nil
}

func (m *X509SVID) GetBundle() []byte {
	if m != nil {
		return m.Bundle
	}
	return nil
}

func init() {
	proto.RegisterType((*X509SVIDRequest)(nil), "X509SVIDRequest")
	proto.RegisterType((*X509SVIDResponse)(nil), "X509SVIDResponse")
	proto.RegisterType((*X509SVID)(nil), "X509SVID")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for SpiffeWorkloadAPI service

type SpiffeWorkloadAPIClient interface {
	// X.509-SVID Profile
	// Fetch all SPIFFE identities the workload is entitled to, as
	// well as related information like trust bundles and CRLs. As
	// this information changes, subsequent messages will be sent.
	FetchX509SVID(ctx context.Context, in *X509SVIDRequest, opts ...grpc.CallOption) (SpiffeWorkloadAPI_FetchX509SVIDClient, error)
}

type spiffeWorkloadAPIClient struct {
	cc *grpc.ClientConn
}

func NewSpiffeWorkloadAPIClient(cc *grpc.ClientConn) SpiffeWorkloadAPIClient {
	return &spiffeWorkloadAPIClient{cc}
}

func (c *spiffeWorkloadAPIClient) FetchX509SVID(ctx context.Context, in *X509SVIDRequest, opts ...grpc.CallOption) (SpiffeWorkloadAPI_FetchX509SVIDClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_SpiffeWorkloadAPI_serviceDesc.Streams[0], c.cc, "/SpiffeWorkloadAPI/FetchX509SVID", opts...)
	if err != nil {
		return nil, err
	}
	x := &spiffeWorkloadAPIFetchX509SVIDClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type SpiffeWorkloadAPI_FetchX509SVIDClient interface {
	Recv() (*X509SVIDResponse, error)
	grpc.ClientStream
}

type spiffeWorkloadAPIFetchX509SVIDClient struct {
	grpc.ClientStream
}

func (x *spiffeWorkloadAPIFetchX509SVIDClient) Recv() (*X509SVIDResponse, error) {
	m := new(X509SVIDResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Server API for SpiffeWorkloadAPI service

type SpiffeWorkloadAPIServer interface {
	// X.509-SVID Profile
	// Fetch all SPIFFE identities the workload is entitled to, as
	// well as related information like trust bundles and CRLs. As
	// this information changes, subsequent messages will be sent.
	FetchX509SVID(*X509SVIDRequest, SpiffeWorkloadAPI_FetchX509SVIDServer) error
}

func RegisterSpiffeWorkloadAPIServer(s *grpc.Server, srv SpiffeWorkloadAPIServer) {
	s.RegisterService(&_SpiffeWorkloadAPI_serviceDesc, srv)
}

func _SpiffeWorkloadAPI_FetchX509SVID_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(X509SVIDRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(SpiffeWorkloadAPIServer).FetchX509SVID(m, &spiffeWorkloadAPIFetchX509SVIDServer{stream})
}

type SpiffeWorkloadAPI_FetchX509SVIDServer interface {
	Send(*X509SVIDResponse) error
	grpc.ServerStream
}

type spiffeWorkloadAPIFetchX509SVIDServer struct {
	grpc.ServerStream
}

func (x *spiffeWorkloadAPIFetchX509SVIDServer) Send(m *X509SVIDResponse) error {
	return x.ServerStream.SendMsg(m)
}

var _SpiffeWorkloadAPI_serviceDesc = grpc.ServiceDesc{
	ServiceName: "SpiffeWorkloadAPI",
	HandlerType: (*SpiffeWorkloadAPIServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "FetchX509SVID",
			Handler:       _SpiffeWorkloadAPI_FetchX509SVID_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "workload.proto",
}

func init() { proto.RegisterFile("workload.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 312 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x91, 0x4d, 0x4f, 0xf2, 0x40,
	0x10, 0xc7, 0xb3, 0xf4, 0x81, 0xc0, 0x00, 0x8f, 0xed, 0x46, 0xcd, 0x06, 0x0f, 0x36, 0xbd, 0xd8,
	0x53, 0x43, 0x30, 0x18, 0xf1, 0xe6, 0x1b, 0x09, 0xe1, 0x62, 0x8a, 0x51, 0x6f, 0x0d, 0xb0, 0xd3,
	0xd8, 0xd0, 0xd0, 0xda, 0x6d, 0xab, 0xbd, 0xf9, 0x51, 0xfd, 0x28, 0x66, 0xfb, 0x66, 0x52, 0xbd,
	0xcd, 0xfc, 0xe7, 0x37, 0x3b, 0x33, 0xfb, 0x87, 0xff, 0xef, 0x41, 0xb4, 0xf3, 0x83, 0x35, 0xb7,
	0xc2, 0x28, 0x88, 0x03, 0x43, 0x83, 0x83, 0x97, 0xe9, 0x78, 0xb6, 0x7a, 0x5a, 0xdc, 0xd9, 0xf8,
	0x96, 0xa0, 0x88, 0x8d, 0x2f, 0x02, 0xea, 0x8f, 0x26, 0xc2, 0x60, 0x2f, 0x90, 0x9e, 0x42, 0x5b,
	0xa4, 0x1e, 0x17, 0x8c, 0xe8, 0x8a, 0xd9, 0x9f, 0xf4, 0xac, 0x9a, 0x28, 0x74, 0xaa, 0x82, 0xb2,
	0x8d, 0x7c, 0xd6, 0xd2, 0x15, 0x73, 0x60, 0xcb, 0x90, 0x3e, 0x82, 0xe6, 0x22, 0xc7, 0x68, 0x1d,
	0x23, 0x77, 0x36, 0xc9, 0x9e, 0xfb, 0x28, 0x98, 0x92, 0xb7, 0x9f, 0x59, 0xcd, 0x01, 0xd6, 0xbc,
	0x42, 0x6f, 0x0a, 0xf2, 0x7e, 0x1f, 0x47, 0x99, 0xad, 0xba, 0x0d, 0x79, 0x74, 0x0b, 0x47, 0x7f,
	0xa2, 0x72, 0x81, 0x1d, 0x66, 0x8c, 0xe8, 0xc4, 0xec, 0xd9, 0x32, 0xa4, 0x87, 0xd0, 0x4e, 0xd7,
	0x7e, 0x82, 0xac, 0xa5, 0x13, 0x73, 0x60, 0x17, 0xc9, 0x55, 0xeb, 0x92, 0x18, 0x9f, 0x04, 0xba,
	0xd5, 0x06, 0xf4, 0x04, 0x7a, 0x22, 0xf4, 0x5c, 0x17, 0x1d, 0x8f, 0x97, 0xed, 0xdd, 0x42, 0x58,
	0x70, 0x59, 0xfc, 0x98, 0x8e, 0x67, 0x8e, 0x3c, 0xb2, 0x7c, 0xa7, 0x2b, 0x85, 0x55, 0xea, 0x71,
	0x6a, 0xc0, 0xb0, 0x2e, 0x3a, 0x72, 0xb8, 0x92, 0x03, 0xfd, 0x0a, 0x58, 0x62, 0x46, 0x8f, 0xa1,
	0x53, 0xdc, 0xce, 0xfe, 0xe5, 0xc5, 0x32, 0x9b, 0x2c, 0x41, 0x5b, 0xe5, 0x43, 0x9e, 0x4b, 0x43,
	0xae, 0x1f, 0x16, 0xf4, 0x02, 0x86, 0x73, 0x8c, 0xb7, 0xaf, 0xf5, 0x6e, 0xaa, 0xd5, 0x70, 0x67,
	0xa4, 0xfd, 0xfa, 0xba, 0x31, 0xd9, 0x74, 0x72, 0x33, 0xcf, 0xbf, 0x03, 0x00, 0x00, 0xff, 0xff,
	0x54, 0xd1, 0x4a, 0xc1, 0xde, 0x01, 0x00, 0x00,
}
