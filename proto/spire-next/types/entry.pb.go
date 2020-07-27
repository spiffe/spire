// Code generated by protoc-gen-go. DO NOT EDIT.
// source: spire-next/types/entry.proto

package types

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Entry struct {
	// Globally unique ID for the entry.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// The SPIFFE ID of the identity described by this entry.
	SpiffeId *SPIFFEID `protobuf:"bytes,2,opt,name=spiffe_id,json=spiffeId,proto3" json:"spiffe_id,omitempty"`
	// Who the entry is delegated to. If the entry describes a node, this is
	// set to the SPIFFE ID of the SPIRE server of the trust domain (e.g.
	// spiffe://example.org/spire/server). Otherwise, it will be set to a node
	// SPIFFE ID.
	ParentId *SPIFFEID `protobuf:"bytes,3,opt,name=parent_id,json=parentId,proto3" json:"parent_id,omitempty"`
	// The selectors which identify which entities match this entry. If this is
	// an entry for a node, these selectors represent selectors produced by
	// node attestation. Otherwise, these selectors represent those produced by
	// workload attestation.
	Selectors []*Selector `protobuf:"bytes,4,rep,name=selectors,proto3" json:"selectors,omitempty"`
	// The time to live for identities issued for this entry (in seconds).
	Ttl int32 `protobuf:"varint,5,opt,name=ttl,proto3" json:"ttl,omitempty"`
	// The names of trust domains the identity described by this entry
	// federates with.
	FederatesWith []string `protobuf:"bytes,6,rep,name=federates_with,json=federatesWith,proto3" json:"federates_with,omitempty"`
	// Whether or not the identity described by this entry is an administrative
	// workload. Administrative workloads are granted additional access to
	// various managerial server APIs, such as entry registration.
	Admin bool `protobuf:"varint,7,opt,name=admin,proto3" json:"admin,omitempty"`
	// Whether or not the identity described by this entry represents a
	// downstream SPIRE server. Downstream SPIRE servers have additional access
	// to various signing APIs, such as those used to sign X.509 CA
	// certificates and publish JWT signing keys.
	Downstream bool `protobuf:"varint,8,opt,name=downstream,proto3" json:"downstream,omitempty"`
	// When the entry expires (seconds since Unix epoch).
	ExpiresAt int64 `protobuf:"varint,9,opt,name=expires_at,json=expiresAt,proto3" json:"expires_at,omitempty"`
	// A list of DNS names associated with the identity described by this entry.
	DnsNames []string `protobuf:"bytes,10,rep,name=dns_names,json=dnsNames,proto3" json:"dns_names,omitempty"`
	// Revision number is bumped every time the entry is updated
	RevisionNumber       int64    `protobuf:"varint,11,opt,name=revision_number,json=revisionNumber,proto3" json:"revision_number,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Entry) Reset()         { *m = Entry{} }
func (m *Entry) String() string { return proto.CompactTextString(m) }
func (*Entry) ProtoMessage()    {}
func (*Entry) Descriptor() ([]byte, []int) {
	return fileDescriptor_e0e2bfec39452b8c, []int{0}
}

func (m *Entry) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Entry.Unmarshal(m, b)
}
func (m *Entry) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Entry.Marshal(b, m, deterministic)
}
func (m *Entry) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Entry.Merge(m, src)
}
func (m *Entry) XXX_Size() int {
	return xxx_messageInfo_Entry.Size(m)
}
func (m *Entry) XXX_DiscardUnknown() {
	xxx_messageInfo_Entry.DiscardUnknown(m)
}

var xxx_messageInfo_Entry proto.InternalMessageInfo

func (m *Entry) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *Entry) GetSpiffeId() *SPIFFEID {
	if m != nil {
		return m.SpiffeId
	}
	return nil
}

func (m *Entry) GetParentId() *SPIFFEID {
	if m != nil {
		return m.ParentId
	}
	return nil
}

func (m *Entry) GetSelectors() []*Selector {
	if m != nil {
		return m.Selectors
	}
	return nil
}

func (m *Entry) GetTtl() int32 {
	if m != nil {
		return m.Ttl
	}
	return 0
}

func (m *Entry) GetFederatesWith() []string {
	if m != nil {
		return m.FederatesWith
	}
	return nil
}

func (m *Entry) GetAdmin() bool {
	if m != nil {
		return m.Admin
	}
	return false
}

func (m *Entry) GetDownstream() bool {
	if m != nil {
		return m.Downstream
	}
	return false
}

func (m *Entry) GetExpiresAt() int64 {
	if m != nil {
		return m.ExpiresAt
	}
	return 0
}

func (m *Entry) GetDnsNames() []string {
	if m != nil {
		return m.DnsNames
	}
	return nil
}

func (m *Entry) GetRevisionNumber() int64 {
	if m != nil {
		return m.RevisionNumber
	}
	return 0
}

// Field mask for Entry fields
type EntryMask struct {
	// spiffe_id field mask
	SpiffeId bool `protobuf:"varint,2,opt,name=spiffe_id,json=spiffeId,proto3" json:"spiffe_id,omitempty"`
	// parent_id field mask
	ParentId bool `protobuf:"varint,3,opt,name=parent_id,json=parentId,proto3" json:"parent_id,omitempty"`
	// selectors field mask
	Selectors bool `protobuf:"varint,4,opt,name=selectors,proto3" json:"selectors,omitempty"`
	// ttl field mask
	Ttl bool `protobuf:"varint,5,opt,name=ttl,proto3" json:"ttl,omitempty"`
	// federates_with field mask
	FederatesWith bool `protobuf:"varint,6,opt,name=federates_with,json=federatesWith,proto3" json:"federates_with,omitempty"`
	// admin field mask
	Admin bool `protobuf:"varint,7,opt,name=admin,proto3" json:"admin,omitempty"`
	// downstream field mask
	Downstream bool `protobuf:"varint,8,opt,name=downstream,proto3" json:"downstream,omitempty"`
	// expires_at field mask
	ExpiresAt bool `protobuf:"varint,9,opt,name=expires_at,json=expiresAt,proto3" json:"expires_at,omitempty"`
	// dns_names field mask
	DnsNames bool `protobuf:"varint,10,opt,name=dns_names,json=dnsNames,proto3" json:"dns_names,omitempty"`
	// revision_number field mask
	RevisionNumber       bool     `protobuf:"varint,11,opt,name=revision_number,json=revisionNumber,proto3" json:"revision_number,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *EntryMask) Reset()         { *m = EntryMask{} }
func (m *EntryMask) String() string { return proto.CompactTextString(m) }
func (*EntryMask) ProtoMessage()    {}
func (*EntryMask) Descriptor() ([]byte, []int) {
	return fileDescriptor_e0e2bfec39452b8c, []int{1}
}

func (m *EntryMask) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_EntryMask.Unmarshal(m, b)
}
func (m *EntryMask) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_EntryMask.Marshal(b, m, deterministic)
}
func (m *EntryMask) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EntryMask.Merge(m, src)
}
func (m *EntryMask) XXX_Size() int {
	return xxx_messageInfo_EntryMask.Size(m)
}
func (m *EntryMask) XXX_DiscardUnknown() {
	xxx_messageInfo_EntryMask.DiscardUnknown(m)
}

var xxx_messageInfo_EntryMask proto.InternalMessageInfo

func (m *EntryMask) GetSpiffeId() bool {
	if m != nil {
		return m.SpiffeId
	}
	return false
}

func (m *EntryMask) GetParentId() bool {
	if m != nil {
		return m.ParentId
	}
	return false
}

func (m *EntryMask) GetSelectors() bool {
	if m != nil {
		return m.Selectors
	}
	return false
}

func (m *EntryMask) GetTtl() bool {
	if m != nil {
		return m.Ttl
	}
	return false
}

func (m *EntryMask) GetFederatesWith() bool {
	if m != nil {
		return m.FederatesWith
	}
	return false
}

func (m *EntryMask) GetAdmin() bool {
	if m != nil {
		return m.Admin
	}
	return false
}

func (m *EntryMask) GetDownstream() bool {
	if m != nil {
		return m.Downstream
	}
	return false
}

func (m *EntryMask) GetExpiresAt() bool {
	if m != nil {
		return m.ExpiresAt
	}
	return false
}

func (m *EntryMask) GetDnsNames() bool {
	if m != nil {
		return m.DnsNames
	}
	return false
}

func (m *EntryMask) GetRevisionNumber() bool {
	if m != nil {
		return m.RevisionNumber
	}
	return false
}

func init() {
	proto.RegisterType((*Entry)(nil), "spire.types.Entry")
	proto.RegisterType((*EntryMask)(nil), "spire.types.EntryMask")
}

func init() {
	proto.RegisterFile("spire-next/types/entry.proto", fileDescriptor_e0e2bfec39452b8c)
}

var fileDescriptor_e0e2bfec39452b8c = []byte{
	// 405 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xb4, 0x93, 0xcf, 0x8e, 0xd3, 0x30,
	0x10, 0xc6, 0x95, 0x84, 0x2c, 0xf6, 0x54, 0x14, 0x64, 0x81, 0x64, 0xb1, 0x0b, 0x44, 0x2b, 0x21,
	0x72, 0x21, 0x41, 0xbb, 0x4f, 0x00, 0x62, 0x57, 0xca, 0x81, 0x15, 0x0a, 0x07, 0x24, 0x2e, 0x51,
	0xba, 0x9e, 0x52, 0x8b, 0x8d, 0x13, 0xd9, 0x2e, 0x6d, 0xdf, 0x80, 0x37, 0xe2, 0xf5, 0x90, 0x9d,
	0x16, 0xd2, 0x3f, 0x94, 0x13, 0xb7, 0xf8, 0xfb, 0xbe, 0x19, 0x4f, 0x7e, 0x99, 0xc0, 0x99, 0xe9,
	0xa4, 0xc6, 0xd7, 0x0a, 0x97, 0x36, 0xb7, 0xab, 0x0e, 0x4d, 0x8e, 0xca, 0xea, 0x55, 0xd6, 0xe9,
	0xd6, 0xb6, 0x6c, 0xe4, 0xdd, 0xcc, 0x1b, 0x4f, 0x5f, 0xec, 0x45, 0x0d, 0xde, 0xe1, 0xad, 0x6d,
	0x75, 0x9f, 0x3e, 0x14, 0xe8, 0xe4, 0x74, 0x8a, 0x52, 0xf4, 0x81, 0xf3, 0x1f, 0x11, 0xc4, 0x57,
	0xae, 0x3d, 0x1b, 0x43, 0x28, 0x05, 0x0f, 0x92, 0x20, 0xa5, 0x65, 0x28, 0x05, 0xbb, 0x00, 0xda,
	0x67, 0x2b, 0x29, 0x78, 0x98, 0x04, 0xe9, 0xe8, 0xe2, 0x49, 0x36, 0xb8, 0x3c, 0xfb, 0xf4, 0xb1,
	0xb8, 0xbe, 0xbe, 0x2a, 0xde, 0x97, 0xa4, 0xcf, 0x15, 0xbe, 0xa6, 0xab, 0x35, 0x2a, 0xeb, 0x6a,
	0xa2, 0xa3, 0x35, 0x7d, 0xae, 0x10, 0xec, 0x12, 0xe8, 0x66, 0x68, 0xc3, 0xef, 0x25, 0xd1, 0x7e,
	0xcd, 0xda, 0x2d, 0xff, 0xe4, 0xd8, 0x23, 0x88, 0xac, 0xbd, 0xe3, 0x71, 0x12, 0xa4, 0x71, 0xe9,
	0x1e, 0xd9, 0x4b, 0x18, 0x4f, 0x51, 0xa0, 0xae, 0x2d, 0x9a, 0x6a, 0x21, 0xed, 0x8c, 0x9f, 0x24,
	0x51, 0x4a, 0xcb, 0x07, 0xbf, 0xd5, 0xcf, 0xd2, 0xce, 0xd8, 0x63, 0x88, 0x6b, 0xd1, 0x48, 0xc5,
	0xef, 0x27, 0x41, 0x4a, 0xca, 0xfe, 0xc0, 0x9e, 0x03, 0x88, 0x76, 0xa1, 0x8c, 0xd5, 0x58, 0x37,
	0x9c, 0x78, 0x6b, 0xa0, 0xb0, 0x67, 0x00, 0xb8, 0x74, 0x23, 0x99, 0xaa, 0xb6, 0x9c, 0x26, 0x41,
	0x1a, 0x95, 0x74, 0xad, 0xbc, 0xb5, 0xec, 0x14, 0xa8, 0x50, 0xa6, 0x52, 0x75, 0x83, 0x86, 0x83,
	0xbf, 0x96, 0x08, 0x65, 0x6e, 0xdc, 0x99, 0xbd, 0x82, 0x87, 0x1a, 0xbf, 0x4b, 0x23, 0x5b, 0x55,
	0xa9, 0x79, 0x33, 0x41, 0xcd, 0x47, 0xbe, 0xc1, 0x78, 0x23, 0xdf, 0x78, 0xf5, 0xfc, 0x67, 0x08,
	0xd4, 0x7f, 0x8a, 0x0f, 0xb5, 0xf9, 0xe6, 0x7a, 0x6e, 0xe3, 0x27, 0x03, 0xce, 0xa7, 0xbb, 0x9c,
	0xc9, 0x00, 0xe8, 0xd9, 0x36, 0x50, 0x67, 0x1e, 0x26, 0x47, 0xfe, 0x4e, 0xce, 0x99, 0xff, 0x89,
	0x1c, 0x39, 0x42, 0xce, 0xbf, 0xc8, 0xbf, 0xc8, 0x91, 0x5d, 0x72, 0xef, 0xde, 0x7c, 0xc9, 0xbe,
	0x4a, 0x3b, 0x9b, 0x4f, 0xb2, 0xdb, 0xb6, 0x59, 0x6f, 0x78, 0xee, 0x57, 0x28, 0xf7, 0x5b, 0x9e,
	0xef, 0xfe, 0x05, 0x93, 0x13, 0xaf, 0x5f, 0xfe, 0x0a, 0x00, 0x00, 0xff, 0xff, 0x10, 0xc1, 0x62,
	0x28, 0x6c, 0x03, 0x00, 0x00,
}
