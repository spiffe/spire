// Code generated by protoc-gen-go. DO NOT EDIT.
// source: keymanager.proto

package keymanager

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	plugin "github.com/spiffe/spire/proto/common/plugin"
	grpc "google.golang.org/grpc"
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

// ConfigureRequest from public import github.com/spiffe/spire/proto/common/plugin/plugin.proto
type ConfigureRequest = plugin.ConfigureRequest

// ConfigureRequest_GlobalConfig from public import github.com/spiffe/spire/proto/common/plugin/plugin.proto
type ConfigureRequest_GlobalConfig = plugin.ConfigureRequest_GlobalConfig

// ConfigureResponse from public import github.com/spiffe/spire/proto/common/plugin/plugin.proto
type ConfigureResponse = plugin.ConfigureResponse

// GetPluginInfoRequest from public import github.com/spiffe/spire/proto/common/plugin/plugin.proto
type GetPluginInfoRequest = plugin.GetPluginInfoRequest

// GetPluginInfoResponse from public import github.com/spiffe/spire/proto/common/plugin/plugin.proto
type GetPluginInfoResponse = plugin.GetPluginInfoResponse

// InitRequest from public import github.com/spiffe/spire/proto/common/plugin/plugin.proto
type InitRequest = plugin.InitRequest

// InitResponse from public import github.com/spiffe/spire/proto/common/plugin/plugin.proto
type InitResponse = plugin.InitResponse

type KeyType int32

const (
	KeyType_UNSPECIFIED_KEY_TYPE KeyType = 0
	KeyType_EC_P256              KeyType = 1
	KeyType_EC_P384              KeyType = 2
	KeyType_RSA_1024             KeyType = 3
	KeyType_RSA_2048             KeyType = 4
	KeyType_RSA_4096             KeyType = 5
)

var KeyType_name = map[int32]string{
	0: "UNSPECIFIED_KEY_TYPE",
	1: "EC_P256",
	2: "EC_P384",
	3: "RSA_1024",
	4: "RSA_2048",
	5: "RSA_4096",
}

var KeyType_value = map[string]int32{
	"UNSPECIFIED_KEY_TYPE": 0,
	"EC_P256":              1,
	"EC_P384":              2,
	"RSA_1024":             3,
	"RSA_2048":             4,
	"RSA_4096":             5,
}

func (x KeyType) String() string {
	return proto.EnumName(KeyType_name, int32(x))
}

func (KeyType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_217d89b504f0b25a, []int{0}
}

type HashAlgorithm int32

const (
	HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM HashAlgorithm = 0
	// These entries (and their values) line up with a subset of the go
	// crypto.Hash constants
	HashAlgorithm_SHA224     HashAlgorithm = 4
	HashAlgorithm_SHA256     HashAlgorithm = 5
	HashAlgorithm_SHA384     HashAlgorithm = 6
	HashAlgorithm_SHA512     HashAlgorithm = 7
	HashAlgorithm_SHA3_224   HashAlgorithm = 10
	HashAlgorithm_SHA3_256   HashAlgorithm = 11
	HashAlgorithm_SHA3_384   HashAlgorithm = 12
	HashAlgorithm_SHA3_512   HashAlgorithm = 13
	HashAlgorithm_SHA512_224 HashAlgorithm = 14
	HashAlgorithm_SHA512_256 HashAlgorithm = 15
)

var HashAlgorithm_name = map[int32]string{
	0:  "UNSPECIFIED_HASH_ALGORITHM",
	4:  "SHA224",
	5:  "SHA256",
	6:  "SHA384",
	7:  "SHA512",
	10: "SHA3_224",
	11: "SHA3_256",
	12: "SHA3_384",
	13: "SHA3_512",
	14: "SHA512_224",
	15: "SHA512_256",
}

var HashAlgorithm_value = map[string]int32{
	"UNSPECIFIED_HASH_ALGORITHM": 0,
	"SHA224":                     4,
	"SHA256":                     5,
	"SHA384":                     6,
	"SHA512":                     7,
	"SHA3_224":                   10,
	"SHA3_256":                   11,
	"SHA3_384":                   12,
	"SHA3_512":                   13,
	"SHA512_224":                 14,
	"SHA512_256":                 15,
}

func (x HashAlgorithm) String() string {
	return proto.EnumName(HashAlgorithm_name, int32(x))
}

func (HashAlgorithm) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_217d89b504f0b25a, []int{1}
}

type PublicKey struct {
	Id                   string   `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Type                 KeyType  `protobuf:"varint,2,opt,name=type,proto3,enum=spire.server.keymanager.KeyType" json:"type,omitempty"`
	PkixData             []byte   `protobuf:"bytes,3,opt,name=pkix_data,json=pkixData,proto3" json:"pkix_data,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PublicKey) Reset()         { *m = PublicKey{} }
func (m *PublicKey) String() string { return proto.CompactTextString(m) }
func (*PublicKey) ProtoMessage()    {}
func (*PublicKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_217d89b504f0b25a, []int{0}
}

func (m *PublicKey) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PublicKey.Unmarshal(m, b)
}
func (m *PublicKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PublicKey.Marshal(b, m, deterministic)
}
func (m *PublicKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PublicKey.Merge(m, src)
}
func (m *PublicKey) XXX_Size() int {
	return xxx_messageInfo_PublicKey.Size(m)
}
func (m *PublicKey) XXX_DiscardUnknown() {
	xxx_messageInfo_PublicKey.DiscardUnknown(m)
}

var xxx_messageInfo_PublicKey proto.InternalMessageInfo

func (m *PublicKey) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *PublicKey) GetType() KeyType {
	if m != nil {
		return m.Type
	}
	return KeyType_UNSPECIFIED_KEY_TYPE
}

func (m *PublicKey) GetPkixData() []byte {
	if m != nil {
		return m.PkixData
	}
	return nil
}

type GenerateKeyRequest struct {
	KeyId                string   `protobuf:"bytes,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	KeyType              KeyType  `protobuf:"varint,2,opt,name=key_type,json=keyType,proto3,enum=spire.server.keymanager.KeyType" json:"key_type,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GenerateKeyRequest) Reset()         { *m = GenerateKeyRequest{} }
func (m *GenerateKeyRequest) String() string { return proto.CompactTextString(m) }
func (*GenerateKeyRequest) ProtoMessage()    {}
func (*GenerateKeyRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_217d89b504f0b25a, []int{1}
}

func (m *GenerateKeyRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GenerateKeyRequest.Unmarshal(m, b)
}
func (m *GenerateKeyRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GenerateKeyRequest.Marshal(b, m, deterministic)
}
func (m *GenerateKeyRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GenerateKeyRequest.Merge(m, src)
}
func (m *GenerateKeyRequest) XXX_Size() int {
	return xxx_messageInfo_GenerateKeyRequest.Size(m)
}
func (m *GenerateKeyRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GenerateKeyRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GenerateKeyRequest proto.InternalMessageInfo

func (m *GenerateKeyRequest) GetKeyId() string {
	if m != nil {
		return m.KeyId
	}
	return ""
}

func (m *GenerateKeyRequest) GetKeyType() KeyType {
	if m != nil {
		return m.KeyType
	}
	return KeyType_UNSPECIFIED_KEY_TYPE
}

type GenerateKeyResponse struct {
	PublicKey            *PublicKey `protobuf:"bytes,1,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *GenerateKeyResponse) Reset()         { *m = GenerateKeyResponse{} }
func (m *GenerateKeyResponse) String() string { return proto.CompactTextString(m) }
func (*GenerateKeyResponse) ProtoMessage()    {}
func (*GenerateKeyResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_217d89b504f0b25a, []int{2}
}

func (m *GenerateKeyResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GenerateKeyResponse.Unmarshal(m, b)
}
func (m *GenerateKeyResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GenerateKeyResponse.Marshal(b, m, deterministic)
}
func (m *GenerateKeyResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GenerateKeyResponse.Merge(m, src)
}
func (m *GenerateKeyResponse) XXX_Size() int {
	return xxx_messageInfo_GenerateKeyResponse.Size(m)
}
func (m *GenerateKeyResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_GenerateKeyResponse.DiscardUnknown(m)
}

var xxx_messageInfo_GenerateKeyResponse proto.InternalMessageInfo

func (m *GenerateKeyResponse) GetPublicKey() *PublicKey {
	if m != nil {
		return m.PublicKey
	}
	return nil
}

type GetPublicKeyRequest struct {
	KeyId                string   `protobuf:"bytes,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetPublicKeyRequest) Reset()         { *m = GetPublicKeyRequest{} }
func (m *GetPublicKeyRequest) String() string { return proto.CompactTextString(m) }
func (*GetPublicKeyRequest) ProtoMessage()    {}
func (*GetPublicKeyRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_217d89b504f0b25a, []int{3}
}

func (m *GetPublicKeyRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetPublicKeyRequest.Unmarshal(m, b)
}
func (m *GetPublicKeyRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetPublicKeyRequest.Marshal(b, m, deterministic)
}
func (m *GetPublicKeyRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetPublicKeyRequest.Merge(m, src)
}
func (m *GetPublicKeyRequest) XXX_Size() int {
	return xxx_messageInfo_GetPublicKeyRequest.Size(m)
}
func (m *GetPublicKeyRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetPublicKeyRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetPublicKeyRequest proto.InternalMessageInfo

func (m *GetPublicKeyRequest) GetKeyId() string {
	if m != nil {
		return m.KeyId
	}
	return ""
}

type GetPublicKeyResponse struct {
	PublicKey            *PublicKey `protobuf:"bytes,1,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *GetPublicKeyResponse) Reset()         { *m = GetPublicKeyResponse{} }
func (m *GetPublicKeyResponse) String() string { return proto.CompactTextString(m) }
func (*GetPublicKeyResponse) ProtoMessage()    {}
func (*GetPublicKeyResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_217d89b504f0b25a, []int{4}
}

func (m *GetPublicKeyResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetPublicKeyResponse.Unmarshal(m, b)
}
func (m *GetPublicKeyResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetPublicKeyResponse.Marshal(b, m, deterministic)
}
func (m *GetPublicKeyResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetPublicKeyResponse.Merge(m, src)
}
func (m *GetPublicKeyResponse) XXX_Size() int {
	return xxx_messageInfo_GetPublicKeyResponse.Size(m)
}
func (m *GetPublicKeyResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_GetPublicKeyResponse.DiscardUnknown(m)
}

var xxx_messageInfo_GetPublicKeyResponse proto.InternalMessageInfo

func (m *GetPublicKeyResponse) GetPublicKey() *PublicKey {
	if m != nil {
		return m.PublicKey
	}
	return nil
}

type GetPublicKeysRequest struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetPublicKeysRequest) Reset()         { *m = GetPublicKeysRequest{} }
func (m *GetPublicKeysRequest) String() string { return proto.CompactTextString(m) }
func (*GetPublicKeysRequest) ProtoMessage()    {}
func (*GetPublicKeysRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_217d89b504f0b25a, []int{5}
}

func (m *GetPublicKeysRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetPublicKeysRequest.Unmarshal(m, b)
}
func (m *GetPublicKeysRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetPublicKeysRequest.Marshal(b, m, deterministic)
}
func (m *GetPublicKeysRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetPublicKeysRequest.Merge(m, src)
}
func (m *GetPublicKeysRequest) XXX_Size() int {
	return xxx_messageInfo_GetPublicKeysRequest.Size(m)
}
func (m *GetPublicKeysRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetPublicKeysRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetPublicKeysRequest proto.InternalMessageInfo

type GetPublicKeysResponse struct {
	PublicKeys           []*PublicKey `protobuf:"bytes,1,rep,name=public_keys,json=publicKeys,proto3" json:"public_keys,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *GetPublicKeysResponse) Reset()         { *m = GetPublicKeysResponse{} }
func (m *GetPublicKeysResponse) String() string { return proto.CompactTextString(m) }
func (*GetPublicKeysResponse) ProtoMessage()    {}
func (*GetPublicKeysResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_217d89b504f0b25a, []int{6}
}

func (m *GetPublicKeysResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetPublicKeysResponse.Unmarshal(m, b)
}
func (m *GetPublicKeysResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetPublicKeysResponse.Marshal(b, m, deterministic)
}
func (m *GetPublicKeysResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetPublicKeysResponse.Merge(m, src)
}
func (m *GetPublicKeysResponse) XXX_Size() int {
	return xxx_messageInfo_GetPublicKeysResponse.Size(m)
}
func (m *GetPublicKeysResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_GetPublicKeysResponse.DiscardUnknown(m)
}

var xxx_messageInfo_GetPublicKeysResponse proto.InternalMessageInfo

func (m *GetPublicKeysResponse) GetPublicKeys() []*PublicKey {
	if m != nil {
		return m.PublicKeys
	}
	return nil
}

type PSSOptions struct {
	SaltLength           int32         `protobuf:"varint,1,opt,name=salt_length,json=saltLength,proto3" json:"salt_length,omitempty"`
	HashAlgorithm        HashAlgorithm `protobuf:"varint,2,opt,name=hash_algorithm,json=hashAlgorithm,proto3,enum=spire.server.keymanager.HashAlgorithm" json:"hash_algorithm,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *PSSOptions) Reset()         { *m = PSSOptions{} }
func (m *PSSOptions) String() string { return proto.CompactTextString(m) }
func (*PSSOptions) ProtoMessage()    {}
func (*PSSOptions) Descriptor() ([]byte, []int) {
	return fileDescriptor_217d89b504f0b25a, []int{7}
}

func (m *PSSOptions) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PSSOptions.Unmarshal(m, b)
}
func (m *PSSOptions) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PSSOptions.Marshal(b, m, deterministic)
}
func (m *PSSOptions) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PSSOptions.Merge(m, src)
}
func (m *PSSOptions) XXX_Size() int {
	return xxx_messageInfo_PSSOptions.Size(m)
}
func (m *PSSOptions) XXX_DiscardUnknown() {
	xxx_messageInfo_PSSOptions.DiscardUnknown(m)
}

var xxx_messageInfo_PSSOptions proto.InternalMessageInfo

func (m *PSSOptions) GetSaltLength() int32 {
	if m != nil {
		return m.SaltLength
	}
	return 0
}

func (m *PSSOptions) GetHashAlgorithm() HashAlgorithm {
	if m != nil {
		return m.HashAlgorithm
	}
	return HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM
}

type SignDataRequest struct {
	KeyId string `protobuf:"bytes,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	Data  []byte `protobuf:"bytes,3,opt,name=data,proto3" json:"data,omitempty"`
	// Types that are valid to be assigned to SignerOpts:
	//	*SignDataRequest_HashAlgorithm
	//	*SignDataRequest_PssOptions
	SignerOpts           isSignDataRequest_SignerOpts `protobuf_oneof:"signer_opts"`
	XXX_NoUnkeyedLiteral struct{}                     `json:"-"`
	XXX_unrecognized     []byte                       `json:"-"`
	XXX_sizecache        int32                        `json:"-"`
}

func (m *SignDataRequest) Reset()         { *m = SignDataRequest{} }
func (m *SignDataRequest) String() string { return proto.CompactTextString(m) }
func (*SignDataRequest) ProtoMessage()    {}
func (*SignDataRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_217d89b504f0b25a, []int{8}
}

func (m *SignDataRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignDataRequest.Unmarshal(m, b)
}
func (m *SignDataRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignDataRequest.Marshal(b, m, deterministic)
}
func (m *SignDataRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignDataRequest.Merge(m, src)
}
func (m *SignDataRequest) XXX_Size() int {
	return xxx_messageInfo_SignDataRequest.Size(m)
}
func (m *SignDataRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_SignDataRequest.DiscardUnknown(m)
}

var xxx_messageInfo_SignDataRequest proto.InternalMessageInfo

func (m *SignDataRequest) GetKeyId() string {
	if m != nil {
		return m.KeyId
	}
	return ""
}

func (m *SignDataRequest) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

type isSignDataRequest_SignerOpts interface {
	isSignDataRequest_SignerOpts()
}

type SignDataRequest_HashAlgorithm struct {
	HashAlgorithm HashAlgorithm `protobuf:"varint,2,opt,name=hash_algorithm,json=hashAlgorithm,proto3,enum=spire.server.keymanager.HashAlgorithm,oneof"`
}

type SignDataRequest_PssOptions struct {
	PssOptions *PSSOptions `protobuf:"bytes,4,opt,name=pss_options,json=pssOptions,proto3,oneof"`
}

func (*SignDataRequest_HashAlgorithm) isSignDataRequest_SignerOpts() {}

func (*SignDataRequest_PssOptions) isSignDataRequest_SignerOpts() {}

func (m *SignDataRequest) GetSignerOpts() isSignDataRequest_SignerOpts {
	if m != nil {
		return m.SignerOpts
	}
	return nil
}

func (m *SignDataRequest) GetHashAlgorithm() HashAlgorithm {
	if x, ok := m.GetSignerOpts().(*SignDataRequest_HashAlgorithm); ok {
		return x.HashAlgorithm
	}
	return HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM
}

func (m *SignDataRequest) GetPssOptions() *PSSOptions {
	if x, ok := m.GetSignerOpts().(*SignDataRequest_PssOptions); ok {
		return x.PssOptions
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*SignDataRequest) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*SignDataRequest_HashAlgorithm)(nil),
		(*SignDataRequest_PssOptions)(nil),
	}
}

type SignDataResponse struct {
	Signature            []byte   `protobuf:"bytes,1,opt,name=signature,proto3" json:"signature,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SignDataResponse) Reset()         { *m = SignDataResponse{} }
func (m *SignDataResponse) String() string { return proto.CompactTextString(m) }
func (*SignDataResponse) ProtoMessage()    {}
func (*SignDataResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_217d89b504f0b25a, []int{9}
}

func (m *SignDataResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignDataResponse.Unmarshal(m, b)
}
func (m *SignDataResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignDataResponse.Marshal(b, m, deterministic)
}
func (m *SignDataResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignDataResponse.Merge(m, src)
}
func (m *SignDataResponse) XXX_Size() int {
	return xxx_messageInfo_SignDataResponse.Size(m)
}
func (m *SignDataResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_SignDataResponse.DiscardUnknown(m)
}

var xxx_messageInfo_SignDataResponse proto.InternalMessageInfo

func (m *SignDataResponse) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

func init() {
	proto.RegisterEnum("spire.server.keymanager.KeyType", KeyType_name, KeyType_value)
	proto.RegisterEnum("spire.server.keymanager.HashAlgorithm", HashAlgorithm_name, HashAlgorithm_value)
	proto.RegisterType((*PublicKey)(nil), "spire.server.keymanager.PublicKey")
	proto.RegisterType((*GenerateKeyRequest)(nil), "spire.server.keymanager.GenerateKeyRequest")
	proto.RegisterType((*GenerateKeyResponse)(nil), "spire.server.keymanager.GenerateKeyResponse")
	proto.RegisterType((*GetPublicKeyRequest)(nil), "spire.server.keymanager.GetPublicKeyRequest")
	proto.RegisterType((*GetPublicKeyResponse)(nil), "spire.server.keymanager.GetPublicKeyResponse")
	proto.RegisterType((*GetPublicKeysRequest)(nil), "spire.server.keymanager.GetPublicKeysRequest")
	proto.RegisterType((*GetPublicKeysResponse)(nil), "spire.server.keymanager.GetPublicKeysResponse")
	proto.RegisterType((*PSSOptions)(nil), "spire.server.keymanager.PSSOptions")
	proto.RegisterType((*SignDataRequest)(nil), "spire.server.keymanager.SignDataRequest")
	proto.RegisterType((*SignDataResponse)(nil), "spire.server.keymanager.SignDataResponse")
}

func init() { proto.RegisterFile("keymanager.proto", fileDescriptor_217d89b504f0b25a) }

var fileDescriptor_217d89b504f0b25a = []byte{
	// 771 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x55, 0x6d, 0x6f, 0xda, 0x48,
	0x10, 0xc6, 0x84, 0xd7, 0x31, 0x10, 0x6b, 0x2f, 0xb9, 0x43, 0xdc, 0xe9, 0x8a, 0x5c, 0x35, 0x22,
	0x69, 0x6a, 0x88, 0x03, 0x28, 0x55, 0x3f, 0x11, 0x42, 0x02, 0x22, 0x69, 0x90, 0x49, 0xa5, 0x26,
	0xaa, 0x64, 0x39, 0x61, 0xb1, 0x2d, 0xc0, 0x76, 0xbd, 0xa6, 0xaa, 0xa5, 0xfe, 0xaf, 0xfe, 0xa1,
	0xfe, 0x88, 0x7e, 0xac, 0x6c, 0xaf, 0x79, 0x49, 0x4a, 0x42, 0xd5, 0x7e, 0xf2, 0xcc, 0xec, 0xf3,
	0xcc, 0xb3, 0x33, 0xb3, 0xbb, 0x06, 0x6e, 0x84, 0xdd, 0x89, 0x62, 0x28, 0x2a, 0xb6, 0x05, 0xcb,
	0x36, 0x1d, 0x13, 0xfd, 0x43, 0x2c, 0xdd, 0xc6, 0x02, 0xc1, 0xf6, 0x27, 0x6c, 0x0b, 0xf3, 0xe5,
	0xc2, 0x91, 0xaa, 0x3b, 0xda, 0xf4, 0x56, 0xb8, 0x33, 0x27, 0x65, 0x62, 0xe9, 0xc3, 0x21, 0x2e,
	0xfb, 0xd0, 0xb2, 0xcf, 0x2b, 0xdf, 0x99, 0x93, 0x89, 0x69, 0x94, 0xad, 0xf1, 0x54, 0xd5, 0xc3,
	0x4f, 0x90, 0x92, 0x37, 0x20, 0xdd, 0x9b, 0xde, 0x8e, 0xf5, 0xbb, 0x2e, 0x76, 0x51, 0x0e, 0xa2,
	0xfa, 0x20, 0xcf, 0x14, 0x99, 0x52, 0x5a, 0x8a, 0xea, 0x03, 0x54, 0x85, 0x98, 0xe3, 0x5a, 0x38,
	0x1f, 0x2d, 0x32, 0xa5, 0x9c, 0x58, 0x14, 0x56, 0xc8, 0x0b, 0x5d, 0xec, 0x5e, 0xb9, 0x16, 0x96,
	0x7c, 0x34, 0xfa, 0x17, 0xd2, 0xd6, 0x48, 0xff, 0x2c, 0x0f, 0x14, 0x47, 0xc9, 0x6f, 0x14, 0x99,
	0x52, 0x46, 0x4a, 0x79, 0x81, 0x13, 0xc5, 0x51, 0x78, 0x0d, 0xd0, 0x19, 0x36, 0xb0, 0xad, 0x38,
	0xb8, 0x8b, 0x5d, 0x09, 0x7f, 0x9c, 0x62, 0xe2, 0xa0, 0x6d, 0x48, 0x8c, 0xb0, 0x2b, 0xcf, 0xc4,
	0xe3, 0x23, 0xec, 0x76, 0x06, 0xe8, 0x0d, 0xa4, 0xbc, 0xf0, 0x2f, 0xed, 0x21, 0x39, 0x0a, 0x0c,
	0xfe, 0x3d, 0xfc, 0xb5, 0xa4, 0x44, 0x2c, 0xd3, 0x20, 0x18, 0x35, 0x00, 0x2c, 0xbf, 0x60, 0x79,
	0x84, 0x5d, 0x5f, 0x8e, 0x15, 0xf9, 0x95, 0x59, 0x67, 0xbd, 0x91, 0xd2, 0x56, 0x68, 0xf2, 0xfb,
	0x5e, 0x66, 0x67, 0xbe, 0xf4, 0x68, 0x11, 0xfc, 0x35, 0x6c, 0x2d, 0xa3, 0xff, 0xdc, 0x46, 0xfe,
	0x5e, 0x4e, 0x4d, 0xe8, 0x4e, 0xf8, 0x0f, 0xb0, 0x7d, 0x2f, 0x4e, 0x35, 0x9b, 0xc0, 0xce, 0x35,
	0x49, 0x9e, 0x29, 0x6e, 0xac, 0x29, 0x0a, 0x33, 0x51, 0xc2, 0x7f, 0x01, 0xe8, 0xf5, 0xfb, 0x97,
	0x96, 0xa3, 0x9b, 0x06, 0x41, 0xcf, 0x80, 0x25, 0xca, 0xd8, 0x91, 0xc7, 0xd8, 0x50, 0x1d, 0xcd,
	0xaf, 0x23, 0x2e, 0x81, 0x17, 0x3a, 0xf7, 0x23, 0xe8, 0x02, 0x72, 0x9a, 0x42, 0x34, 0x59, 0x19,
	0xab, 0xa6, 0xad, 0x3b, 0xda, 0x84, 0x8e, 0x72, 0x67, 0xa5, 0x6c, 0x5b, 0x21, 0x5a, 0x23, 0x44,
	0x4b, 0x59, 0x6d, 0xd1, 0xe5, 0xbf, 0x31, 0xb0, 0xd9, 0xd7, 0x55, 0xc3, 0x3b, 0x4d, 0x4f, 0x1c,
	0x1f, 0x04, 0xb1, 0x85, 0x33, 0xe8, 0xdb, 0xe8, 0xf2, 0xf7, 0x76, 0xd3, 0x8e, 0xdc, 0xdb, 0x0f,
	0x3a, 0x05, 0xd6, 0x22, 0x44, 0x36, 0x83, 0x76, 0xe4, 0x63, 0xfe, 0x1c, 0x9f, 0xaf, 0x6e, 0xe9,
	0xac, 0x73, 0xed, 0x88, 0x04, 0x16, 0x21, 0xd4, 0x3b, 0xce, 0x02, 0x4b, 0x74, 0xd5, 0xc0, 0xb6,
	0x97, 0x8a, 0xf0, 0x15, 0xe0, 0xe6, 0x55, 0xd2, 0xe9, 0xfd, 0x07, 0x69, 0x0f, 0xa2, 0x38, 0x53,
	0x1b, 0xfb, 0x95, 0x66, 0xa4, 0x79, 0x60, 0x4f, 0x85, 0x24, 0xbd, 0x03, 0x28, 0x0f, 0x5b, 0xef,
	0xde, 0xf6, 0x7b, 0xad, 0x66, 0xe7, 0xb4, 0xd3, 0x3a, 0x91, 0xbb, 0xad, 0x6b, 0xf9, 0xea, 0xba,
	0xd7, 0xe2, 0x22, 0x88, 0x85, 0x64, 0xab, 0x29, 0xf7, 0xc4, 0x5a, 0x9d, 0x63, 0x42, 0xe7, 0xf0,
	0xa8, 0xca, 0x45, 0x51, 0x06, 0x52, 0x52, 0xbf, 0x21, 0x1f, 0x54, 0xc4, 0x2a, 0xb7, 0x11, 0x7a,
	0x62, 0xa5, 0x7a, 0xc4, 0xc5, 0x42, 0xaf, 0x5a, 0x79, 0x5d, 0xe7, 0xe2, 0x7b, 0x5f, 0x19, 0xc8,
	0x2e, 0x35, 0x05, 0xfd, 0x0f, 0x85, 0x45, 0xbd, 0x76, 0xa3, 0xdf, 0x96, 0x1b, 0xe7, 0x67, 0x97,
	0x52, 0xe7, 0xaa, 0x7d, 0xc1, 0x45, 0x10, 0x40, 0xa2, 0xdf, 0x6e, 0x88, 0x62, 0x95, 0x8b, 0x85,
	0x76, 0xad, 0xce, 0xc5, 0xa9, 0xed, 0xe9, 0x27, 0xa8, 0x5d, 0x3b, 0x10, 0xb9, 0xa4, 0xa7, 0xe7,
	0xc5, 0x65, 0x8f, 0x01, 0x73, 0xaf, 0x56, 0xe7, 0xd8, 0x99, 0xe7, 0xb1, 0x32, 0x33, 0xcf, 0xe3,
	0x65, 0x51, 0x0e, 0x20, 0xc8, 0xe1, 0x33, 0x73, 0x8b, 0x7e, 0xad, 0xce, 0x6d, 0x8a, 0xdf, 0x63,
	0x00, 0x5d, 0xec, 0x5e, 0x04, 0xb3, 0x40, 0x1a, 0xb0, 0x0b, 0x2f, 0x04, 0x7a, 0xb9, 0x72, 0x68,
	0x0f, 0x5f, 0xac, 0xc2, 0xfe, 0x7a, 0x60, 0x3a, 0xb9, 0x11, 0x64, 0x16, 0x2f, 0x24, 0x7a, 0x8c,
	0xfd, 0xe0, 0x61, 0x29, 0xbc, 0x5a, 0x13, 0x4d, 0xc5, 0x0c, 0xc8, 0x2e, 0xdd, 0x7e, 0xb4, 0x1e,
	0x3f, 0x7c, 0x3d, 0x0a, 0xc2, 0xba, 0x70, 0xaa, 0x27, 0x43, 0x2a, 0x3c, 0xaa, 0xa8, 0xb4, 0x92,
	0x7b, 0xef, 0xce, 0x16, 0x76, 0xd7, 0x40, 0x52, 0x81, 0x1b, 0x48, 0x37, 0x4d, 0x63, 0xa8, 0xab,
	0x53, 0x1b, 0xa3, 0x17, 0x94, 0x17, 0xfc, 0xd3, 0x04, 0xfa, 0x33, 0x9b, 0xad, 0x87, 0xe9, 0x77,
	0x9e, 0x82, 0xd1, 0xdc, 0xc3, 0xa0, 0x59, 0xfe, 0x72, 0xc7, 0x18, 0x9a, 0x68, 0xf7, 0xa7, 0xc4,
	0x25, 0x4c, 0xa8, 0xb1, 0xb7, 0x0e, 0x34, 0xd0, 0x39, 0xce, 0xdc, 0xc0, 0xbc, 0xc4, 0x5e, 0xe4,
	0x36, 0xe1, 0xff, 0x7e, 0x0f, 0x7f, 0x04, 0x00, 0x00, 0xff, 0xff, 0xc6, 0xd3, 0xf0, 0x11, 0xe5,
	0x07, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// KeyManagerClient is the client API for KeyManager service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type KeyManagerClient interface {
	// Generates a new key
	GenerateKey(ctx context.Context, in *GenerateKeyRequest, opts ...grpc.CallOption) (*GenerateKeyResponse, error)
	// Get a public key by key id
	GetPublicKey(ctx context.Context, in *GetPublicKeyRequest, opts ...grpc.CallOption) (*GetPublicKeyResponse, error)
	// Gets all public keys
	GetPublicKeys(ctx context.Context, in *GetPublicKeysRequest, opts ...grpc.CallOption) (*GetPublicKeysResponse, error)
	// Signs data with private key
	SignData(ctx context.Context, in *SignDataRequest, opts ...grpc.CallOption) (*SignDataResponse, error)
	// Applies the plugin configuration
	Configure(ctx context.Context, in *plugin.ConfigureRequest, opts ...grpc.CallOption) (*plugin.ConfigureResponse, error)
	// Returns the version and related metadata of the installed plugin
	GetPluginInfo(ctx context.Context, in *plugin.GetPluginInfoRequest, opts ...grpc.CallOption) (*plugin.GetPluginInfoResponse, error)
}

type keyManagerClient struct {
	cc *grpc.ClientConn
}

func NewKeyManagerClient(cc *grpc.ClientConn) KeyManagerClient {
	return &keyManagerClient{cc}
}

func (c *keyManagerClient) GenerateKey(ctx context.Context, in *GenerateKeyRequest, opts ...grpc.CallOption) (*GenerateKeyResponse, error) {
	out := new(GenerateKeyResponse)
	err := c.cc.Invoke(ctx, "/spire.server.keymanager.KeyManager/GenerateKey", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyManagerClient) GetPublicKey(ctx context.Context, in *GetPublicKeyRequest, opts ...grpc.CallOption) (*GetPublicKeyResponse, error) {
	out := new(GetPublicKeyResponse)
	err := c.cc.Invoke(ctx, "/spire.server.keymanager.KeyManager/GetPublicKey", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyManagerClient) GetPublicKeys(ctx context.Context, in *GetPublicKeysRequest, opts ...grpc.CallOption) (*GetPublicKeysResponse, error) {
	out := new(GetPublicKeysResponse)
	err := c.cc.Invoke(ctx, "/spire.server.keymanager.KeyManager/GetPublicKeys", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyManagerClient) SignData(ctx context.Context, in *SignDataRequest, opts ...grpc.CallOption) (*SignDataResponse, error) {
	out := new(SignDataResponse)
	err := c.cc.Invoke(ctx, "/spire.server.keymanager.KeyManager/SignData", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyManagerClient) Configure(ctx context.Context, in *plugin.ConfigureRequest, opts ...grpc.CallOption) (*plugin.ConfigureResponse, error) {
	out := new(plugin.ConfigureResponse)
	err := c.cc.Invoke(ctx, "/spire.server.keymanager.KeyManager/Configure", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyManagerClient) GetPluginInfo(ctx context.Context, in *plugin.GetPluginInfoRequest, opts ...grpc.CallOption) (*plugin.GetPluginInfoResponse, error) {
	out := new(plugin.GetPluginInfoResponse)
	err := c.cc.Invoke(ctx, "/spire.server.keymanager.KeyManager/GetPluginInfo", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// KeyManagerServer is the server API for KeyManager service.
type KeyManagerServer interface {
	// Generates a new key
	GenerateKey(context.Context, *GenerateKeyRequest) (*GenerateKeyResponse, error)
	// Get a public key by key id
	GetPublicKey(context.Context, *GetPublicKeyRequest) (*GetPublicKeyResponse, error)
	// Gets all public keys
	GetPublicKeys(context.Context, *GetPublicKeysRequest) (*GetPublicKeysResponse, error)
	// Signs data with private key
	SignData(context.Context, *SignDataRequest) (*SignDataResponse, error)
	// Applies the plugin configuration
	Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error)
	// Returns the version and related metadata of the installed plugin
	GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error)
}

func RegisterKeyManagerServer(s *grpc.Server, srv KeyManagerServer) {
	s.RegisterService(&_KeyManager_serviceDesc, srv)
}

func _KeyManager_GenerateKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GenerateKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyManagerServer).GenerateKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/spire.server.keymanager.KeyManager/GenerateKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyManagerServer).GenerateKey(ctx, req.(*GenerateKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyManager_GetPublicKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetPublicKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyManagerServer).GetPublicKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/spire.server.keymanager.KeyManager/GetPublicKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyManagerServer).GetPublicKey(ctx, req.(*GetPublicKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyManager_GetPublicKeys_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetPublicKeysRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyManagerServer).GetPublicKeys(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/spire.server.keymanager.KeyManager/GetPublicKeys",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyManagerServer).GetPublicKeys(ctx, req.(*GetPublicKeysRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyManager_SignData_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignDataRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyManagerServer).SignData(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/spire.server.keymanager.KeyManager/SignData",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyManagerServer).SignData(ctx, req.(*SignDataRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyManager_Configure_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(plugin.ConfigureRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyManagerServer).Configure(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/spire.server.keymanager.KeyManager/Configure",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyManagerServer).Configure(ctx, req.(*plugin.ConfigureRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyManager_GetPluginInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(plugin.GetPluginInfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyManagerServer).GetPluginInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/spire.server.keymanager.KeyManager/GetPluginInfo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyManagerServer).GetPluginInfo(ctx, req.(*plugin.GetPluginInfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _KeyManager_serviceDesc = grpc.ServiceDesc{
	ServiceName: "spire.server.keymanager.KeyManager",
	HandlerType: (*KeyManagerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GenerateKey",
			Handler:    _KeyManager_GenerateKey_Handler,
		},
		{
			MethodName: "GetPublicKey",
			Handler:    _KeyManager_GetPublicKey_Handler,
		},
		{
			MethodName: "GetPublicKeys",
			Handler:    _KeyManager_GetPublicKeys_Handler,
		},
		{
			MethodName: "SignData",
			Handler:    _KeyManager_SignData_Handler,
		},
		{
			MethodName: "Configure",
			Handler:    _KeyManager_Configure_Handler,
		},
		{
			MethodName: "GetPluginInfo",
			Handler:    _KeyManager_GetPluginInfo_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "keymanager.proto",
}
