package ciphertrustkms

import (
	"encoding/json"
	"strings"
	"time"
)

// CryptoUsageMask type is a Cryptographic Usage Mask defined by KMIP
type CryptoUsageMask uint32

const (
	// AES algorithm
	AES = "AES"
	// AES128 algorithm size 128
	AES128 = 128
	// AES192 AES algorithm size 128
	AES192 = 192
	// AES256 AES algorithm size 128
	AES256 = 256
	// TDES algorithm
	TDES = "TDES"
	// TDES128 algorithm size 128
	TDES128 = 128
	// TDES192 algorithm size 192
	TDES192 = 192
	// RSA algorithm
	RSA = "RSA"
	// RSA512 RSA algorithm size 512
	RSA512 = 512
	// RSA1024 RSA algorithm size 1024
	RSA1024 = 1024
	// RSA2048 RSA algorithm size 2048
	RSA2048 = 2048
	// RSA4096 RSA algorithm size 4096
	RSA4096 = 4096
	// HMACSHA1 algorithm
	HMACSHA1 = "HMAC-SHA1"
	// HMACSHA1Size128 HMACSHA1 algorithm size 128
	HMACSHA1Size128 = 128
	// HMACSHA1Size160 HMACSHA1 algorithm size 160
	HMACSHA1Size160 = 160
	// HMACSHA256 algorithm
	HMACSHA256 = "HMAC-SHA256"
	// HMACSHA256Size128 HMACSHA256 algorithm size 128
	HMACSHA256Size128 = 128
	// HMACSHA256Size256 HMACSHA256 algorithm size 256
	HMACSHA256Size256 = 256
	// HMACSHA384 algorithm
	HMACSHA384 = "HMAC-SHA384"
	// HMACSHA384Size192 HMACSHA384 algorithm size 192
	HMACSHA384Size192 = 192
	// HMACSHA384Size384 HMACSHA384 algorithm size 384
	HMACSHA384Size384 = 384
	// HMACSHA512 algorithm
	HMACSHA512 = "HMAC-SHA512"
	// HMACSHA512Size256 HMACSHA512 algorithm size 256
	HMACSHA512Size256 = 256
	// HMACSHA512Size512 HMACSHA512 algorithm size 512
	HMACSHA512Size512 = 512
	// SEED algorithm
	SEED = "SEED"
	// SEED128 aSEED lgorithm size 128
	SEED128 = 128
	// ARIA algorithm
	ARIA = "ARIA"
	// ARIA128 ARIA algorithm size 128
	ARIA128 = 128
	// ARIA192 ARIA algorithm size 192
	ARIA192 = 192
	// ARIA256 ARIA algorithm size 256
	ARIA256 = 256
	// EC algorithm
	EC = "EC"
	// EC224 EC algorithm size 224
	EC224 = 224
	// EC256 EC algorithm size 224
	EC256 = 256
	// EC384 EC algorithm size 224
	EC384 = 384
	// EC512 EC algorithm size 224
	EC512 = 512
	// EC521 EC algorithm size 224
	EC521 = 521
	// Secp224k1 EC curve id
	Secp224k1 = "secp224k1"
	// Secp256k1 EC curve id
	Secp256k1 = "secp256k1"
	// Secp224r1 EC curve id
	Secp224r1 = "secp224r1"
	// Secp384r1 EC curve id
	Secp384r1 = "secp384r1"
	// Secp521r1 EC curve id
	Secp521r1 = "secp521r1"
	// Prime256v1 EC curve id
	Prime256v1 = "prime256v1"
	// BrainpoolP224r1 EC curve id
	BrainpoolP224r1 = "brainpoolP224r1"
	// BrainpoolP256r1 EC curve id
	BrainpoolP256r1 = "brainpoolP256r1"
	// BrainpoolP384r1 EC curve id
	BrainpoolP384r1 = "brainpoolP384r1"
	// BrainpoolP512r1 EC curve id
	BrainpoolP512r1 = "brainpoolP512r1"
	// BrainpoolP224t1 EC curve id
	BrainpoolP224t1 = "brainpoolP224t1"
	// BrainpoolP256t1 EC curve id
	BrainpoolP256t1 = "brainpoolP256t1"
	// BrainpoolP384t1 EC curve id
	BrainpoolP384t1 = "brainpoolP384t1"
	// BrainpoolP512t1 EC curve id
	BrainpoolP512t1 = "brainpoolP512t1"

	// UsageMaskSign Usage Mask for sign operation
	UsageMaskSign CryptoUsageMask = 0x00000001 // 1
	// UsageMaskVerify Usage Mask for mask operation
	UsageMaskVerify CryptoUsageMask = 0x00000002 // 2
	// UsageMaskEncrypt Usage Mask for encrypt operation
	UsageMaskEncrypt CryptoUsageMask = 0x00000004 // 4
	// UsageMaskDecrypt Usage Mask for decrypt operation
	UsageMaskDecrypt CryptoUsageMask = 0x00000008 //8
	// UsageMaskWrapKey Usage Mask for wrap key operation
	UsageMaskWrapKey CryptoUsageMask = 0x00000010 // 16
	// UsageMaskUnwrapKey Usage Mask for unwrap key operation
	UsageMaskUnwrapKey CryptoUsageMask = 0x00000020 // 32
	// UsageMaskExport Usage Mask for undefined operation
	UsageMaskExport CryptoUsageMask = 0x00000040 // 64
	// UsageMaskMACGenerate Usage Mask for MAC generate operation
	UsageMaskMACGenerate CryptoUsageMask = 0x00000080 // 128
	// UsageMaskMACVerify Usage Mask for MAC verify operation
	UsageMaskMACVerify CryptoUsageMask = 0x00000100 // 256
	// UsageMaskDeriveKey Usage Mask for derive key operation
	UsageMaskDeriveKey CryptoUsageMask = 0x00000200 // 512
	// UsageMaskContentCommitment Usage Mask for content commitment operation
	UsageMaskContentCommitment CryptoUsageMask = 0x00000400 // 1024
	// UsageMaskKeyAgreement Usage Mask for key agreement operation
	UsageMaskKeyAgreement CryptoUsageMask = 0x00000800 // 2048
	// UsageMaskCertificateSign Usage Mask for certificate sign operation
	UsageMaskCertificateSign CryptoUsageMask = 0x00001000 // 4096
	// UsageMaskCRLSign Usage Mask for CRL sign operation
	UsageMaskCRLSign CryptoUsageMask = 0x00002000 // 8192
	// UsageMaskGenerateCryptogram Usage Mask for generate cryptogram operation
	UsageMaskGenerateCryptogram CryptoUsageMask = 0x00004000 // 16384
	// UsageMaskValidateCryptogram Usage Mask for validate cryptogram operation
	UsageMaskValidateCryptogram CryptoUsageMask = 0x00008000 // 32768
	// UsageMaskTranslateEncrypt Usage Mask for translate encrypt operation
	UsageMaskTranslateEncrypt CryptoUsageMask = 0x00010000 // 65536
	// UsageMaskTranslateDecrypt Usage Mask for translate decrypt operation
	UsageMaskTranslateDecrypt CryptoUsageMask = 0x00020000 // 131072
	// UsageMaskTranslateWrap Usage Mask for translate wrap operation
	UsageMaskTranslateWrap CryptoUsageMask = 0x00040000 // 262144
	// UsageMaskTranslateUnwrap Usage Mask for translate unwrap operation
	UsageMaskTranslateUnwrap CryptoUsageMask = 0x00080000 // 524288

	// Usage Mask Extensions

	// UsageMaskFPEEncrypt Usage Mask for FPE encrypt operation
	UsageMaskFPEEncrypt CryptoUsageMask = 0x00100000 // 1048576
	// UsageMaskFPEDecrypt Usage Mask for FPE decrypt operation
	UsageMaskFPEDecrypt CryptoUsageMask = 0x00200000 // 2097152

	// UsageMaskUsageBlob Usage Mask (12) for Usage 'blob'
	UsageMaskUsageBlob = UsageMaskEncrypt + UsageMaskDecrypt
	// UsageMaskUsageFPE Usage Mask (3145728) for Usage 'fpe'
	UsageMaskUsageFPE = UsageMaskFPEEncrypt + UsageMaskFPEDecrypt
	// UsageMaskUsageSign Usage Mask (3) for Usage 'sign'
	UsageMaskUsageSign = UsageMaskSign + UsageMaskVerify
	// UsageMaskUsageHMAC Usage Mask (384) for Usage 'hmac'
	UsageMaskUsageHMAC = UsageMaskMACGenerate + UsageMaskMACVerify
	// UsageMaskUsageAny Usage Mask (4194303) for Usage 'any'. It includes all usages except UsageMaskExport
	UsageMaskUsageAny = UsageMaskSign + UsageMaskVerify + UsageMaskEncrypt + UsageMaskDecrypt +
		UsageMaskWrapKey + UsageMaskUnwrapKey + UsageMaskExport + UsageMaskMACGenerate + UsageMaskMACVerify +
		UsageMaskDeriveKey + UsageMaskContentCommitment + UsageMaskKeyAgreement + UsageMaskCertificateSign +
		UsageMaskCRLSign + UsageMaskGenerateCryptogram + UsageMaskValidateCryptogram + UsageMaskTranslateEncrypt +
		UsageMaskTranslateDecrypt + UsageMaskTranslateWrap + UsageMaskTranslateUnwrap + UsageMaskFPEEncrypt +
		UsageMaskFPEDecrypt

	// CertificateTypeX509PEM specifies x.509 PEM certificate type, and goes into the CertType variable
	CertificateTypeX509PEM = "x509-pem"
	// CertificateTypeX509DER specifies x.509 DER certificate type, and goes into the CertType variable
	CertificateTypeX509DER = "x509-der"
	// CertificateTypePGP specifies PGP certificate type, and goes into the CertType variable
	CertificateTypePGP = "pgp"

	// AES128CBCHMACSHA256 onwards are constants to specify Content Encryption Algorithm for supporting JWE format of export
	// AES128CBCHMACSHA256 represents AES-CBC + HMAC-SHA256 (128)
	AES128CBCHMACSHA256 = "AES_128_CBC_HMAC_SHA_256"
	// AES192CBCHMACSHA384 represents ES-CBC + HMAC-SHA384 (192)
	AES192CBCHMACSHA384 = "AES_192_CBC_HMAC_SHA_384"
	// AES256CBCHMACSHA512 represents AES-CBC + HMAC-SHA512 (256)
	AES256CBCHMACSHA512 = "AES_256_CBC_HMAC_SHA_512"
	// AES128GCM represents AES-GCM (128)
	AES128GCM = "AES_128_GCM"
	// AES192GCM represents AES-GCM (192)
	AES192GCM = "AES_192_GCM"
	// AES256GCM represents AES-GCM (256)
	AES256GCM = "AES_256_GCM"

	// ED25519 onwards are Constants to specify Key Management Algorithm for supporting JWE format of export
	ED25519 = "ED25519"
	// RSA15 represents RSA-PKCS1v1.5
	RSA15 = "RSA1_5"
	// RSAOAEPSHA1 represents RSA_OAEP_SHA1
	RSAOAEPSHA1 = "RSA_OAEP_SHA1"
	// RSAOAEPSHA256 represents RSA_OAEP_SHA256
	RSAOAEPSHA256 = "RSA_OAEP_SHA256"
	// AESKEYWRAP128 represents AES key wrap (128)
	AESKEYWRAP128 = "AES_KEY_WRAP_128"
	// AESKEYWRAP192 represents AES key wrap (192)
	AESKEYWRAP192 = "AES_KEY_WRAP_192"
	// AESKEYWRAP256 represents AES key wrap (256)
	AESKEYWRAP256 = "AES_KEY_WRAP_256"
	// DirectEncryption represents DIRECT_ENCRYPTION
	DirectEncryption = "DIRECT_ENCRYPTION"
	// ECDHES represents ECDH_ES
	ECDHES = "ECDH_ES"
	// ECDHESAES128KEYWRAP represents ECDH-ES + AES key wrap (128)
	ECDHESAES128KEYWRAP = "ECDH_ES_AES_128_KEY_WRAP"
	// ECDHESAES192KEYWRAP represents ECDH-ES + AES key wrap (192)
	ECDHESAES192KEYWRAP = "ECDH_ES_AES_192_KEY_WRAP"
	// ECDHESAES256KEYWRAP represents ECDH-ES + AES key wrap (256)
	ECDHESAES256KEYWRAP = "ECDH_ES_AES_256_KEY_WRAP"
	// AES128GCMKEYWRAP represents AES-GCM key wrap (128)
	AES128GCMKEYWRAP = "AES_128_GCM_KEY_WRAP"
	// AES192GCMKEYWRAP represents AES-GCM key wrap (192)
	AES192GCMKEYWRAP = "AES_192_GCM_KEY_WRAP"
	// AES256GCMKEYWRAP represents AES-GCM key wrap (256)
	AES256GCMKEYWRAP = "AES_256_GCM_KEY_WRAP"
	// PBES2HMACSHA256AES128KeyWrap represents PBES2 + HMAC-SHA256 + AES key wrap (128)
	PBES2HMACSHA256AES128KeyWrap = "PBES2_HMAC_SHA_256_AES_128_KEY_WRAP"
	// PBES2HMACSHA384AES192KeyWrap represents PBES2 + HMAC-SHA384 + AES key wrap (192)
	PBES2HMACSHA384AES192KeyWrap = "PBES2_HMAC_SHA_384_AES_192_KEY_WRAP"
	// PBES2HMACSHA512AES256KeyWrap represents PBES2 + HMAC-SHA512 + AES key wrap (256)
	PBES2HMACSHA512AES256KeyWrap = "PBES2_HMAC_SHA_512_AES_256_KEY_WRAP"

	// SHA1 Hashing Algorithm
	SHA1 = "SHA1"
	// SHA224 Hashing Algorithm
	SHA224 = "SHA224"
	// SHA256 Hashing Algorithm
	SHA256 = "SHA256"
	// SHA384 Hashing Algorithm
	SHA384 = "SHA384"
	// SHA512 Hashing Algorithm
	SHA512 = "SHA512"
)

// Revocation Reason values for the Revoke operation.
const (
	RevocationReasonUnspecified          = "Unspecified"
	RevocationReasonKeyCompromise        = "KeyCompromise"
	RevocationReasonCACompromise         = "CACompromise"
	RevocationReasonAffiliationChanged   = "AffiliationChanged"
	RevocationReasonSuperseded           = "Superseded"
	RevocationReasonCessationOfOperation = "CessationOfOperation"
	RevocationReasonPrivilegeWithdrawn   = "PrivilegeWithdrawn"
)

// Reactivation Reason values for the Reactivate operation.
const (
	DeactivatedToActiveProtectStop = "DeactivatedToActiveProtectStop"
	DeactivatedToActive            = "DeactivatedToActive"
	ActiveProtectStopToActive      = "ActiveProtectStopToActive"
)

// IsSet to determine if the given all bits of CryptoUsageMask is set
func (m CryptoUsageMask) IsSet(u CryptoUsageMask) bool {
	return m&u == u
}

// ToCryptoUsageMask converts Usage string to CryptoUsageMask
func ToCryptoUsageMask(usage string) CryptoUsageMask {
	var um CryptoUsageMask
	switch strings.ToLower(usage) {
	case `blob`, `encrypt`:
		um = UsageMaskUsageBlob
	case `fpe`:
		um = UsageMaskUsageFPE
	case `any`:
		um = UsageMaskUsageAny
	case `hmac`:
		um = UsageMaskUsageHMAC
	case `sign`:
		um = UsageMaskUsageSign
	default:
		return 0
	}
	return um
}

// KeysEndpoint wraps the /vault/keys endpoint.
//type KeysEndpoint Client

// KeyAlias is a structure that holds the KMIP name attribute
type KeyAlias struct {
	Alias string `json:"alias"`
	Type  string `json:"type"`
	Index int    `json:"index"`
}

// KeyAliasPatchInput is used to specify parameters for adding, deleting or modifying KMIP name attributes
type KeyAliasPatchInput struct {
	Alias string `json:"alias"`
	Type  string `json:"type"`
	Index *int   `json:"index,omitempty"`
}

// WrapKeyParams used for wrapping the material in the response
type WrapKeyParams struct {
	WrapPublicKey            string                  `json:"wrapPublicKey,omitempty" url:"-"`
	WrapKeyName              string                  `json:"wrapKeyName,omitempty" url:"-"`
	WrapKeyNameIDType        string                  `json:"wrapKeyIDType,omitempty"  url:"-"`
	Padded                   bool                    `json:"padded,omitempty" url:"-"`
	WrapPublicKeyPadding     string                  `json:"wrapPublicKeyPadding,omitempty" url:"-"`
	WrappingMethod           string                  `json:"wrappingMethod,omitempty"  url:"-"`
	WrappingEncryptionAlgo   string                  `json:"wrappingEncryptionAlgo,omitempty"  url:"-"`
	WrappingHashAlgo         string                  `json:"wrappingHashAlgo,omitempty"  url:"-"`
	WrapIV                   string                  `json:"wrapIV,omitempty"  url:"-"`
	MacSignKeyIdentifier     string                  `json:"macSignKeyIdentifier,omitempty" url:"-"`
	MacSignKeyIdentifierType string                  `json:"macSignKeyIdentifierType,omitempty" url:"-"`
	MacSignBytes             string                  `json:"macSignBytes,omitempty" url:"-"`
	SigningAlgo              string                  `json:"signingAlgo,omitempty" url:"-"`
	WrapHKDF                 *HkdfExportParameters   `json:"wrapHKDF,omitempty" url:"-"`
	WrapPBE                  *PBEExportParameters    `json:"wrapPBE,omitempty" url:"-"`
	PemWrap                  bool                    `json:"pemWrap,omitempty" url:"-"`
	WrapRSAAES               *RSAAESExportParameters `json:"wrapRSAAES,omitempty" url:"-"`
}

// Object Types for create operation
const (
	ObjectTypeCertificate  = "Certificate"
	ObjectTypeSymmetricKey = "Symmetric Key"
	ObjectTypePublicKey    = "Public Key"
	ObjectTypePrivateKey   = "Private Key"
	ObjectTypeSplitKey     = "Split Key"
	ObjectTypeTemplate     = "Template"
	ObjectTypeSecretData   = "Secret Data"
	ObjectTypeOpaqueObject = "Opaque Object"
	ObjectTypePGPKey       = "PGP Key"
)

// SplitKeyInfo contains information associated with a KMIP split key object.
type SplitKeyInfo struct {
	SKParts             int    `json:"splitKeyParts,omitempty"`
	SKKeyPartIdentifier int    `json:"splitKeyPartIdentifier,omitempty"`
	SKThreshold         int    `json:"splitKeyThreshold,omitempty"`
	SKMethod            int    `json:"splitKeyMethod,omitempty"`
	SKPrimeFieldSize    string `json:"splitKeyPrimeFieldSize,omitempty"`
}

// CreateKeyParams are the params to create a key
type CreateKeyParams struct {
	Name          string `json:"name,omitempty" url:"-"`
	PublicKeyName string `json:"publicKeyName,omitempty" url:"-"`
	// Usage is deprecated, use UsageMask
	Usage string `json:"usage,omitempty" url:"-"`
	// UsageMask replaces Usage
	UsageMask             CryptoUsageMask            `json:"usageMask,omitempty" url:"-"`
	Meta                  interface{}                `json:"meta,omitempty" url:"-"`
	Algorithm             string                     `json:"algorithm,omitempty" url:"-"`
	Size                  int                        `json:"size,omitempty" url:"-"`
	CurveID               string                     `json:"curveid,omitempty" url:"-"`
	Format                string                     `json:"format,omitempty" url:"-"`
	Encoding              string                     `json:"encoding,omitempty" url:"-"`
	Unexportable          bool                       `json:"unexportable,omitempty" url:"-"`
	Undeletable           bool                       `json:"undeletable,omitempty" url:"-"`
	NeverExported         bool                       `json:"neverExported,omitempty" url:"-"`
	NeverExportable       bool                       `json:"neverExportable,omitempty" url:"-"`
	Material              string                     `json:"material,omitempty" url:"-"`
	ReturnExisting        bool                       `json:"-" url:"returnExisting,omitempty"`
	IncludeMaterial       bool                       `json:"-" url:"includeMaterial,omitempty"`
	EmptyMaterial         bool                       `json:"emptyMaterial,omitempty" url:"-"`
	DefaultIV             string                     `json:"defaultIV,omitempty" url:"-"`
	ActivationDate        *time.Time                 `json:"activationDate,omitempty" url:"-"`
	DeactivationDate      *time.Time                 `json:"deactivationDate,omitempty" url:"-"`
	ArchiveDate           *time.Time                 `json:"archiveDate,omitempty" url:"-"`
	RotationDate          *time.Time                 `json:"rotationDate,omitempty" url:"-"`
	RotationFrequencyDays string                     `json:"rotationFrequencyDays,omitempty" url:"-"`
	ProcessStartDate      *time.Time                 `json:"processStartDate,omitempty" url:"-"`
	ProtectStopDate       *time.Time                 `json:"protectStopDate,omitempty" url:"-"`
	State                 string                     `json:"state,omitempty" url:"-"`
	Aliases               []KeyAlias                 `json:"aliases,omitempty" url:"-"`
	PublicKeyParameters   KeyPostPublicKeyParameters `json:"publicKeyParameters,omitempty" url:"-"`
	WrapKeyParams
	CertType                 string                `json:"certType,omitempty" url:"-"`
	ObjectType               string                `json:"objectType,omitempty" url:"-"`
	Password                 string                `json:"password,omitempty" url:"-"`
	SecretDataLink           string                `json:"secretDataLink,omitempty" url:"-"`
	SecretDataEncoding       string                `json:"secretDataEncoding,omitempty" url:"-"`
	HkdfCreateParameters     *HkdfCreateParameters `json:"hkdfCreateParameters,omitempty" url:"-"`
	UUID                     string                `json:"uuid,omitempty" url:"-"`
	MUID                     string                `json:"muid,omitempty" url:"-"`
	KeyID                    string                `json:"keyId,omitempty" url:"-"`
	ID                       string                `json:"id,omitempty" url:"-"`
	XTS                      bool                  `json:"xts,omitempty" url:"-"`
	GenerateKeyID            bool                  `json:"generateKeyId,omitempty" url:"-"`
	DestroyDate              *time.Time            `json:"destroyDate,omitempty" url:"-"`
	CompromiseOccurrenceDate *time.Time            `json:"compromiseOccurrenceDate,omitempty" url:"-"`
	CompromiseDate           *time.Time            `json:"compromiseDate,omitempty" url:"-"`
	RevocationReason         string                `json:"revocationReason,omitempty" url:"-"`
	RevocationMessage        string                `json:"revocationMessage,omitempty" url:"-"`
	IDSize                   *int                  `json:"idSize,omitempty" url:"-"`
	Labels                   map[string]string     `json:"labels,omitempty" url:"-"`
}

// KeyPostPublicKeyParameters - Post body in create and export key requests for public key.
type KeyPostPublicKeyParameters struct {
	ID                    string          `json:"id,omitempty" url:"-"`
	Name                  string          `json:"name"`
	UsageMask             CryptoUsageMask `json:"usageMask"`
	Meta                  interface{}     `json:"meta,omitempty"`
	ActivationDate        *time.Time      `json:"activationDate,omitempty"`
	DeactivationDate      *time.Time      `json:"deactivationDate,omitempty"`
	ArchiveDate           *time.Time      `json:"archiveDate,omitempty"`
	RotationDate          *time.Time      `json:"rotationDate,omitempty" url:"-"`
	RotationFrequencyDays string          `json:"rotationFrequencyDays,omitempty" url:"-"`
	State                 string          `json:"state,omitempty"`
	Aliases               []KeyAlias      `json:"aliases,omitempty"`
	Unexportable          *bool           `json:"unexportable,omitempty" url:"-"`
	Undeletable           *bool           `json:"undeletable,omitempty" url:"-"`
}

// CreateKeyVersionParams are the params to create a new version of an
// existing key
type CreateKeyVersionParams struct {
	IncludeMaterial bool       `json:"-" url:"includeMaterial,omitempty"`
	Type            string     `json:"-" url:"type,omitempty"`
	DefaultIV       string     `json:"defaultIV,omitempty" url:"-"`
	Material        string     `json:"material,omitempty" url:"-"`
	Aliases         []KeyAlias `json:"aliases,omitempty" url:"-"`
	Offset          int        `json:"offset,omitempty" url:"-"`
	Format          string     `json:"format,omitempty" url:"-"`
	Encoding        string     `json:"encoding,omitempty" url:"-"`
	WrapKeyParams
	CertType string             `json:"certType,omitempty" url:"-"`
	IDSize   *int               `json:"idSize,omitempty" url:"-"`
	Labels   map[string]*string `json:"labels,omitempty" url:"-"`
	UUID     string             `json:"uuid,omitempty" url:"-"`
	MUID     string             `json:"muid,omitempty" url:"-"`
	KeyID    string             `json:"keyId,omitempty" url:"-"`
}

// FindKeysResponse is the response to commands that return a set of keys
type FindKeysResponse struct {
	PagingInfo
	Keys []Key `json:"resources"`
}

// FindListKeyLabelsResponse is the response to commands that return a set of labels
type FindListKeyLabelsResponse struct {
	PagingInfo
	Labels []Labels `json:"resources"`
}

// GetKeyParams are the params to get a key
type GetKeyParams struct {
	// Usage is deprecated, use UsageMask
	Usage string `url:"usage,omitempty"`
	// UsageMask replaces Usage
	UsageMask CryptoUsageMask `url:"usageMask,omitempty"`
	Version   *int            `url:"version,omitempty"`
	Type      string          `url:"type,omitempty"`
	// If Meta is not nil, attempt to unmarshal the key's meta property into it.
	// The value of a Meta should be a pointer to a value, just as if it
	// were the `v` argument to json.Unmarshal()
	Meta interface{} `url:"-"`
}

// ExportKeyParams are the params to export a key
type ExportKeyParams struct {
	Type               string `json:"-" url:"type,omitempty"`
	Version            *int   `json:"-" url:"version,omitempty"`
	Format             string `json:"format,omitempty" url:"-"`
	Encoding           string `json:"encoding,omitempty" url:"-"`
	Password           string `json:"password,omitempty" url:"-"`
	SecretDataEncoding string `json:"secretDataEncoding,omitempty" url:"-"`
	WrapKeyParams
	// If Meta is not nil, attempt to unmarshal the key's meta property into it.
	// The value of a Meta should be a pointer to a value, just as if it
	// were the `v` argument to json.Unmarshal()
	Meta           interface{}          `json:"-" url:"-"`
	WrapJWE        *JWEExportParameters `json:"wrapJWE,omitempty" url:"-"`
	CombineXts     bool                 `json:"combineXts,omitempty" url:"-"`
	SecretDataLink string               `json:"secretDataLink,omitempty" url:"-"`
}

// UpdateKeyParams are the params to update a key
type UpdateKeyParams struct {
	KeyIdentifierOptions
	Meta                  interface{}          `json:"meta,omitempty"`
	Unexportable          *bool                `json:"unexportable,omitempty"`
	Undeletable           *bool                `json:"undeletable,omitempty"`
	ActivationDate        *time.Time           `json:"activationDate,omitempty"`
	ProcessStartDate      *time.Time           `json:"processStartDate,omitempty"`
	ProtectStopDate       *time.Time           `json:"protectStopDate,omitempty"`
	DeactivationDate      *time.Time           `json:"deactivationDate,omitempty"`
	RotationDate          *time.Time           `json:"rotationDate,omitempty" url:"-"`
	RotationFrequencyDays string               `json:"rotationFrequencyDays,omitempty" url:"-"`
	Aliases               []KeyAliasPatchInput `json:"aliases,omitempty"`
	MUID                  string               `json:"muid,omitempty"`
	KeyID                 string               `json:"keyId,omitempty"`
	AllVersions           *bool                `json:"allVersions,omitempty"`
	UsageMask             *CryptoUsageMask     `json:"usageMask,omitempty"`
	Labels                map[string]*string   `json:"labels,omitempty"`
}

type CloneKeyParams struct {
	KeyIdentifierOptions
	IncludeMaterial bool        `json:"-" url:"includeMaterial,omitempty"`
	NewKeyName      string      `json:"newKeyName,omitempty" url:"-"`
	Meta            interface{} `json:"meta,omitempty" url:"-"`
	IDSize          *int        `json:"idSize,omitempty" url:"-"`
}

// DNFields decomposes certificate distinguished name
type DNFields struct {
	CommonName         string   `json:"cn,omitempty"`
	Organization       []string `json:"o,omitempty"`
	OrganizationalUnit []string `json:"ou,omitempty"`
	Email              []string `json:"mail,omitempty"`
	Country            []string `json:"c,omitempty"`
	Province           []string `json:"st,omitempty"`
	StreetAddress      []string `json:"street,omitempty"`
	Locality           []string `json:"l,omitempty"`
	UID                []string `json:"uid,omitempty"`
	SerialNumber       string   `json:"sn,omitempty"`
	Title              []string `json:"t,omitempty"`
	DomainComponent    []string `json:"dc,omitempty"`
	DNQualifier        []string `json:"dnq,omitempty"`
}

// ANFields decomposes certificate alternative name
type ANFields struct {
	DNS          []string `json:"dns,omitempty"`
	IPAddress    []string `json:"ipAddress,omitempty"`
	URI          []string `json:"uri,omitempty"`
	EmailAddress []string `json:"emailAddress,omitempty"`
}

// CertificateFields contains information that is extracted from a certificate.
// Public key info is not here, but in the Key::Algorithm, Key::Size and Key::PublicKey
type CertificateFields struct {
	CertType                  string    `json:"certType,omitempty"`
	CertLength                int       `json:"certLength,omitempty"`
	X509SerialNumber          string    `json:"x509SerialNumber,omitempty"`
	SerialNumber              string    `json:"serialNumber,omitempty"`
	DigitalSignatureAlgorithm string    `json:"dsalg,omitempty"`
	IssuerDNFields            *DNFields `json:"issuerDNFields,omitempty"`
	SubjectDNFields           *DNFields `json:"subjectDNFields,omitempty"`
	IssuerANFields            *ANFields `json:"issuerANFields,omitempty"`
	SubjectANFields           *ANFields `json:"subjectANFields,omitempty"`
}

// HkdfCreateParameters : For Key creation using HKDF
type HkdfCreateParameters struct {
	HkdfParameters
	// Key name used as a master key for HKDF
	IkmKeyName string `json:"ikmKeyName,omitempty"`
}

// HkdfExportParameters : For Key Export using HKDF Wrap
type HkdfExportParameters struct {
	HkdfParameters
	// The desired OKM length in integer
	OkmLen int `json:"okmLen,omitempty"`
}

// HkdfParameters : Common parameters of HKDF in Create and Export Key
type HkdfParameters struct {
	HashAlgorithm string `json:"hashAlgorithm,omitempty"`

	// Random HEX bytes of any length
	Salt string `json:"salt,omitempty"`

	// Random HEX bytes of any length
	Info string `json:"info,omitempty"`
}

// PBEExportParameters : For Key Export using PBE key derivation
type PBEExportParameters struct {
	PBEParameters

	// User provided or random HEX bytes of any length greater than 16 bytes
	Salt string `json:"salt,omitempty"`

	// User provided purpose that acts as prefix to the above salt
	Purpose string `json:"purpose,omitempty"`
}

// PBEParameters : Common parameters of PBE in Create and Export Key
type PBEParameters struct {
	HashAlgorithm string `json:"hashAlgorithm,omitempty"`

	// Random HEX bytes of any length
	Password string `json:"password,omitempty"`

	// Password secret indentifier
	// User cannot pass both password and passworidentifier
	PasswordIdentifier string `json:"passwordidentifier,omitempty"`

	// type of the Passwordidentifier, it could be of type id, name or slug
	PasswordIdentifierType string `json:"passwordidentifiertype,omitempty"`

	// The desired key length in integer
	DkLen int `json:"dklen,omitempty"`

	// Iteration count
	Iteration int `json:"iteration,omitempty"`
}

// RSAAESExportParameters : For Key Export using RSA AES export
type RSAAESExportParameters struct {

	// Size of AES key, valid value are 128, 192, 256
	AesKeySize int `json:"aesKeySize,omitempty"`

	// Padding used for RSA wrap, valid values are oaep, oaep256, oaep384, oaep512
	Padding string `json:"padding,omitempty"`
}

// JWEExportParameters : For Key Export using JWE format
type JWEExportParameters struct {
	// JWTIdentifier is unique identifier for the JWT used by SFDC for replay detection(jti)
	JWTIdentifier string `json:"jwtIdentifier,omitempty"`

	// Content encryption algorithm
	ContentEncryptionAlgorithm string `json:"contentEncryptionAlgorithm,omitempty"`

	// Key management algorithm
	KeyEncryptionAlgorithm string `json:"keyEncryptionAlgorithm,omitempty"`

	// Key identifier to be used as "kid" parameter in JWE material and JWE header.
	// Defaults to key id.
	KeyIdentifier string `json:"keyIdentifier,omitempty"`
}

// JWEMaterialData : For JWE material data
type JWEMaterialData struct {
	// "Kid" The unique ID of the key as defined by the customer.
	// This will be registered with Salesforce, and will be the resource requested by Salesforce when the key
	// is required. Allowed characters are "a-z A-Z 0-9 . - _"
	// Valid examples might be a number "10", a string "2018_data_key", a UUID "982c375b-f46b-4423-8c2d-4d1a69152a0b".
	Kid string `json:"kid,omitempty"`

	// "JWE" The AES key wrapped in a JWE
	JWE string `json:"jwe,omitempty"`
}

// KeyIdentifierOptions are query parameters which change how the key identifier in the path is interpreted.
type KeyIdentifierOptions struct {
	// Type: Optional, indicates the type of identifier.  If empty, identifier type is inferred.  Valid values
	// are id, uri, name, slug, and alias
	Type string `url:"type,omitempty" json:"-" `
	// Version: Optional, only valid when identifier type is name.  Selects a specific version of the key.
	// If empty, the latest version is selected.
	Version *int `url:"version,omitempty" json:"-" `
}

// RevokeKeyParams are the options to the revoke operation.
type RevokeKeyParams struct {
	KeyIdentifierOptions

	// Reason: Required, see RevocationReasonXXX constants for valid values.
	Reason string `json:"reason"`

	// Message: Optional
	Message string `json:"message,omitempty"`

	// CompromiseOccurrenceDate: Optional, only valid if revocation reason is KeyCompromise or CACompromise.
	CompromiseOccurrenceDate *time.Time `json:"compromiseOccurrenceDate,omitempty"`
}

// ReactivateKeyParams are the options to the reactivate operation.
type ReactivateKeyParams struct {
	KeyIdentifierOptions

	// Reason: Required, see ReactivationReasonXXX constants for valid values.
	Reason string `json:"reason"`

	// Message: Optional
	Message string `json:"message,omitempty"`
}

// ArchiveKeyParams are the options to the archive operation.
type ArchiveKeyParams struct {
	KeyIdentifierOptions
}

// RecoverKeyParams are the options to the recover operation.
type RecoverKeyParams struct {
	KeyIdentifierOptions
}

// DeleteKeyParams are the options to the delete operation.
type DeleteKeyParams struct {
	KeyIdentifierOptions
}

// DestroyKeyParams are the options to the delete operation.
type DestroyKeyParams struct {
	KeyIdentifierOptions
}

// SignResponse is the response to the SignVerify operation.
type SignResponse struct {
	Signature  string `json:"data"`
	KeyID      string `json:"keyId"`
	KeyVersion int    `json:"keyVersion"`
}

// Key is an ncryptify key
type Key struct {
	Resource
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updatedAt"`
	Material  string    `json:"material,omitempty"`
	// Usage is deprecated, use UsageMask
	Usage string `json:"usage,omitempty" validate:"required,key-usage"`
	// UsageMask replaces Usage
	UsageMask                CryptoUsageMask    `json:"usageMask,omitempty"`
	Meta                     json.RawMessage    `json:"meta"`
	Version                  int                `json:"version"`
	Algorithm                string             `json:"algorithm"`
	Size                     int                `json:"size,omitempty"`
	CurveID                  string             `json:"curveid,omitempty"`
	Format                   string             `json:"format,omitempty"`
	Encoding                 string             `json:"encoding,omitempty"`
	Unexportable             bool               `json:"unexportable"`
	Undeletable              bool               `json:"undeletable"`
	NeverExported            bool               `json:"neverExported"`
	NeverExportable          bool               `json:"neverExportable"`
	EmptyMaterial            bool               `json:"emptyMaterial"`
	PublicKey                string             `json:"publickey,omitempty"`
	DefaultIV                string             `json:"defaultIV,omitempty"`
	Sha1Fingerprint          string             `json:"sha1Fingerprint,omitempty"`
	Sha256Fingerprint        string             `json:"sha256Fingerprint,omitempty"`
	ObjectType               string             `json:"objectType"`
	ActivationDate           *time.Time         `json:"activationDate,omitempty"`
	DeactivationDate         *time.Time         `json:"deactivationDate,omitempty"`
	RotationDate             *time.Time         `json:"rotationDate,omitempty" url:"-"`
	RotationFrequencyDays    string             `json:"rotationFrequencyDays,omitempty" url:"-"`
	ArchiveDate              *time.Time         `json:"archiveDate,omitempty"`
	DestroyDate              *time.Time         `json:"destroyDate,omitempty"`
	CompromiseOccurrenceDate *time.Time         `json:"compromiseOccurrenceDate,omitempty"`
	CompromiseDate           *time.Time         `json:"compromiseDate,omitempty"`
	RevocationReason         string             `json:"revocationReason,omitempty"`
	RevocationMessage        string             `json:"revocationMessage,omitempty"`
	ProcessStartDate         *time.Time         `json:"processStartDate,omitempty"`
	ProtectStopDate          *time.Time         `json:"protectStopDate,omitempty"`
	State                    string             `json:"state,omitempty"`
	Aliases                  []KeyAlias         `json:"aliases,omitempty"`
	Links                    []Link             `json:"links,omitempty"`
	CertFields               *CertificateFields `json:"certFields,omitempty"`
	SKInfo                   *SplitKeyInfo      `json:"splitKeyInfo,omitempty"`
	PGPKeyVersion            int                `json:"pgpKeyVersion,omitempty"`
	UUID                     string             `json:"uuid,omitempty"`
	MUID                     string             `json:"muid,omitempty"`
	KeyID                    string             `json:"keyId,omitempty"`
	MacSignBytes             string             `json:"macSignBytes,omitempty"`
	IDSize                   int                `json:"idSize,omitempty"`
	PbeSalt                  string             `json:"pbeSalt,omitempty"`
	PbePurpose               string             `json:"pbePurpose,omitempty"`
	Labels                   map[string]string  `json:"labels,omitempty"`
}

// ListKeysParams are the params to find keys
type ListKeysParams struct {
	Skip              int             `json:"-" url:"skip,omitempty"`
	Limit             int             `json:"-" url:"limit,omitempty"`
	Name              string          `json:"-" url:"name,omitempty"`
	State             string          `json:"-" url:"state,omitempty"`
	Alias             string          `json:"-" url:"alias,omitempty"`
	LinkType          string          `json:"-" url:"linkType,omitempty"`
	Fields            string          `json:"-" url:"fields,omitempty"`
	UsageMask         CryptoUsageMask `json:"-" url:"usageMask,omitempty"`
	Meta              *string         `json:"-" url:"metaContains,omitempty"`
	ObjectType        string          `json:"-" url:"objectType,omitempty"`
	Sha1Fingerprint   string          `json:"-" url:"sha1Fingerprint,omitempty"`
	Sha256Fingerprint string          `json:"-" url:"sha256Fingerprint,omitempty"`
	Algorithm         string          `json:"-" url:"algorithm,omitempty"`
	Size              int             `json:"-" url:"size,omitempty"`
	ID                string          `json:"-" url:"id,omitempty"`
	UUID              string          `json:"-" url:"uuid,omitempty"`
	MUID              string          `json:"-" url:"muid,omitempty"`
	KeyID             string          `json:"-" url:"keyId,omitempty"`
	CompareIDWithUUID string          `json:"-" url:"compareIDWithUUID,omitempty"`
	// To support multiple object types as object type only support one
	MultiObjectTypes []string `json:"-" url:"objectType,omitempty"`
	Version          *int     `json:"version,omitempty" url:"version,omitempty"`
	Labels           string   `json:"-" url:"labels,omitempty"`
}

// ListLabelsParams are the params to find labels
type ListLabelsParams struct {
	Skip  int    `json:"-" url:"skip,omitempty"`
	Limit int    `json:"-" url:"limit,omitempty"`
	Label string `json:"-" url:"label,omitempty"`
}

// KeyResponse for exporting keys along with material for internal use
type KeyResponse struct {
	*Key
	Material     string `json:"material,omitempty" gorm:"-"`
	Format       string `json:"format,omitempty" gorm:"-"`
	Encoding     string `json:"encoding,omitempty" gorm:"-"`
	MacSignBytes string `json:"macSignBytes,omitempty" gorm:"-"`
}

/*
// KeysPath returns an option which appends the base keys collection endpoint to the path.
func (k *KeysEndpoint) KeysPath() requester.Option {
	return requester.AppendPath(k.VaultPrefix, k.KeysPrefix)
}

// KeyLabelsPath returns an option which appends the base keys collection endpoint to the path.
func (k *KeysEndpoint) KeyLabelsPath() requester.Option {
	return requester.AppendPath(k.VaultPrefix, k.ListLabelsPrefix)
}

// KeyPath returns an option which appends the key resource endpoint to the path.
// Identifier is the id/name/etc of a key.
func (k *KeysEndpoint) KeyPath(identifier string) requester.Option {
	return optList{k.KeysPath(), requester.AppendPath(url.PathEscape(identifier))}
}

// VersionsPath returns an option which appends the key versions collection endpoint to the path.
// Identifier is the id/name/etc of a key.
func (k *KeysEndpoint) VersionsPath(identifier string) requester.Option {
	return optList{k.KeyPath(identifier), requester.AppendPath("versions/")}
}

// RevokePath returns an option which appends the key revoke endpoint to the path.
// Identifier is the id/name/etc of a key.
func (k *KeysEndpoint) RevokePath(identifier string) requester.Option {
	return optList{k.KeyPath(identifier), requester.AppendPath("revoke")}
}

// ReactivatePath returns an option which appends the key reactivate endpoint to the path.
// Identifier is the id/name/etc of a key.
func (k *KeysEndpoint) ReactivatePath(identifier string) requester.Option {
	return optList{k.KeyPath(identifier), requester.AppendPath("reactivate")}
}

// DestroyPath returns an option which appends the destroy key endpoint to the path.
// Identifier is the id/name/etc of a key.
func (k *KeysEndpoint) DestroyPath(identifier string) requester.Option {
	return optList{k.KeyPath(identifier), requester.AppendPath("destroy")}
}

// ArchivePath returns an option which appends the key archive endpoint to the path.
// Identifier is the id/name/etc of a key.
func (k *KeysEndpoint) ArchivePath(identifier string) requester.Option {
	return optList{k.KeyPath(identifier), requester.AppendPath("archive")}
}

// RecoverPath returns an option which appends the key recover endpoint to the path.
// Identifier is the id/name/etc of a key.
func (k *KeysEndpoint) RecoverPath(identifier string) requester.Option {
	return optList{k.KeyPath(identifier), requester.AppendPath("recover")}
}

// ExportPath returns an option which appends the key export endpoint to the path.
// Identifier is the id/name/etc of a key.
func (k *KeysEndpoint) ExportPath(identifier string) requester.Option {
	return optList{k.KeyPath(identifier), requester.AppendPath("export")}
}

// ClonePath returns an option which appends the key clone endpoint to the path.
// Identifier is the id/name/etc of a key.
func (k *KeysEndpoint) ClonePath(identifier string) requester.Option {
	return optList{k.KeyPath(identifier), requester.AppendPath("clone")}
}

// SlingWithCtx returns an object you can use to make requests on the keys
// endpoint which are not yet reflected in the methods.
//
// Deprecated: use requester.Requester methods instead
func (k *KeysEndpoint) SlingWithCtx(ctx context.Context) *sling.Sling {
	return (*Client)(k).SlingWithCtx(ctx).Path(k.VaultPrefix).Path(k.KeysPrefix)
}

// Create a key
func (k *KeysEndpoint) Create(ctx context.Context, params CreateKeyParams, opts ...requester.Option) (*Key, *http.Response, error) {
	return k.receiveKey(ctx, nil,
		optList{
			requester.Post(),
			k.KeysPath(),
			requester.QueryParams(params),
			requester.Body(params),
			optList(opts),
		},
	)
}

// Get a key
// `identifier` can be the key name, ID, or URI
func (k *KeysEndpoint) Get(ctx context.Context, identifier string, opts ...requester.Option) (*Key, *http.Response, error) {
	return k.GetWithParams(ctx, identifier, GetKeyParams{}, opts...)
}

// GetWithParams gets a key, with options
func (k *KeysEndpoint) GetWithParams(ctx context.Context, identifier string, params GetKeyParams, opts ...requester.Option) (*Key, *http.Response, error) {
	return k.receiveKey(ctx, params.Meta, optList{
		requester.Get(),
		k.KeyPath(identifier),
		requester.QueryParams(params),
		optList(opts),
	})
}

// List lists keys, with filter options
func (k *KeysEndpoint) List(ctx context.Context, params ListKeysParams, opts ...requester.Option) ([]Key, PagingInfo, *http.Response, error) {
	results := FindKeysResponse{}
	resp, _, err := k.ReceiveContext(ctx, &results,
		requester.Get(),
		k.KeysPath(),
		requester.QueryParams(params),
		optList(opts))
	return results.Keys, results.PagingInfo, resp, err
}

// GetVersions of a key
// `identifier` can be the key name, ID, or URI
func (k *KeysEndpoint) GetVersions(ctx context.Context, identifier string, opts ...requester.Option) ([]Key, PagingInfo, *http.Response, error) {
	return k.ListVersions(ctx, identifier, ListKeysParams{}, opts...)
}

// ListVersions of a key
// `identifier` can be the key name, ID, or URI
func (k *KeysEndpoint) ListVersions(ctx context.Context, identifier string, params ListKeysParams, opts ...requester.Option) ([]Key, PagingInfo, *http.Response, error) {
	results := FindKeysResponse{}
	resp, _, err := k.ReceiveContext(ctx, &results,
		requester.Get(),
		k.VersionsPath(identifier),
		requester.QueryParams(params),
		optList(opts),
	)
	return results.Keys, results.PagingInfo, resp, err
}

// CreateVersion creates a new version of an existing key
// `identifier` can be the key name, ID, or URI
func (k *KeysEndpoint) CreateVersion(ctx context.Context, identifier string, opts ...requester.Option) (*Key, *http.Response, error) {
	return k.CreateVersionWithParams(ctx, identifier, CreateKeyVersionParams{}, opts...)
}

// CreateVersionWithParams creates a new version of an existing key
// ID can be a key name, ID, or URI
func (k *KeysEndpoint) CreateVersionWithParams(ctx context.Context, identifier string, params CreateKeyVersionParams, opts ...requester.Option) (*Key, *http.Response, error) {
	return k.receiveKey(ctx, nil, optList{
		requester.Post(),
		k.VersionsPath(identifier),
		requester.QueryParams(params),
		requester.Body(params),
		optList(opts),
	})
}

// Delete a key
func (k *KeysEndpoint) Delete(ctx context.Context, identifier string, params DeleteKeyParams, opts ...requester.Option) (*http.Response, error) {
	return k.SendContext(ctx, requester.Delete(), k.KeyPath(identifier), optList{
		requester.QueryParams(params),
		optList(opts),
	})
}

// Destroy a key material
func (k *KeysEndpoint) Destroy(ctx context.Context, identifier string, params DestroyKeyParams, opts ...requester.Option) (*Key, *http.Response, error) {
	return k.receiveKey(ctx, nil, optList{
		requester.Post(),
		k.DestroyPath(identifier),
		requester.QueryParams(params),
		optList(opts),
	})
}

// Find keys
// Deprecated: use List
func (k *KeysEndpoint) Find(ctx context.Context, params ListKeysParams, opts ...requester.Option) ([]Key, PagingInfo, *http.Response, error) {
	return k.List(ctx, params, opts...)
}

// ExportWithParams exports a key with its secret material
func (k *KeysEndpoint) ExportWithParams(ctx context.Context, identifier string, params ExportKeyParams, opts ...requester.Option) (*Key, *http.Response, error) {
	return k.receiveKey(ctx, params.Meta, optList{
		requester.Post(),
		k.ExportPath(identifier),
		requester.QueryParams(params),
		requester.Body(params),
		optList(opts),
	})
}

// CloneWithParams clones the key
func (k *KeysEndpoint) CloneWithParams(ctx context.Context, identifier string, params CloneKeyParams, opts ...requester.Option) (*Key, *http.Response, error) {
	return k.receiveKey(ctx, nil, optList{
		requester.Post(),
		k.ClonePath(identifier),
		requester.QueryParams(params),
		requester.Body(params),
		optList(opts),
	})
}

// Revoke transitions a key to Deactivated, Compromised, or DestroyedCompromised, depending on the reason
// and the key's start state.
func (k *KeysEndpoint) Revoke(ctx context.Context, identifier string, params RevokeKeyParams, opts ...requester.Option) (*Key, *http.Response, error) {
	return k.receiveKey(ctx, nil, optList{
		requester.Post(),
		k.RevokePath(identifier),
		requester.Body(&params),
		requester.QueryParams(params.KeyIdentifierOptions),
		optList(opts),
	})
}

// Reactive transitions a key to Active from Active-ProtectectStop, Active-Deactivated depending on the reason
func (k *KeysEndpoint) Reactivate(ctx context.Context, identifier string, params ReactivateKeyParams, opts ...requester.Option) (*Key, *http.Response, error) {
	return k.receiveKey(ctx, nil, optList{
		requester.Post(),
		k.ReactivatePath(identifier),
		requester.Body(&params),
		requester.QueryParams(params.KeyIdentifierOptions),
		optList(opts),
	})
}

// Archive marks a key as archived.
func (k *KeysEndpoint) Archive(ctx context.Context, identifier string, params ArchiveKeyParams, opts ...requester.Option) (*Key, *http.Response, error) {
	return k.receiveKey(ctx, nil, optList{
		requester.Post(),
		k.ArchivePath(identifier),
		requester.Body(&params),
		requester.QueryParams(params.KeyIdentifierOptions),
		optList(opts),
	})
}

// Recover unarchives an archived key.
func (k *KeysEndpoint) Recover(ctx context.Context, identifier string, params RecoverKeyParams, opts ...requester.Option) (*Key, *http.Response, error) {
	return k.receiveKey(ctx, nil, optList{
		requester.Post(),
		k.RecoverPath(identifier),
		requester.Body(&params),
		requester.QueryParams(params.KeyIdentifierOptions),
		optList(opts),
	})
}

// Update : Updates a key given a name.
// identifier - key name
// ku - data to update
// Returns:
// On success, key pointer (error is nil). On failure, error provides an explanation.
func (k *KeysEndpoint) Update(ctx context.Context, identifier string, params UpdateKeyParams, opts ...requester.Option) (*Key, *http.Response, error) {
	return k.receiveKey(ctx, nil, optList{
		requester.Patch(),
		k.KeyPath(identifier),
		requester.Body(params),
		requester.QueryParams(params.KeyIdentifierOptions),
		optList(opts),
	})
}

// UpdatePatch : Patches a key
// identifier - key name
// ku - data to update
// Returns:
// On success, key pointer (error is nil). On failure, error provides an explanation.
//
// Deprecated: Use Update()
func (k *KeysEndpoint) UpdatePatch(ctx context.Context, identifier string, params UpdateKeyParams, opts ...requester.Option) (*Key, *http.Response, error) {
	return k.Update(ctx, identifier, params, opts...)
}

func (k *KeysEndpoint) receiveKey(ctx context.Context, meta interface{}, opts requester.Option) (*Key, *http.Response, error) {
	var key Key
	resp, _, err := k.ReceiveContext(ctx, &key, opts)
	if err == nil && meta != nil && len(key.Meta) > 0 {
		err = json.Unmarshal(key.Meta, meta)
	}
	return &key, resp, err
}

// List labels with filter options
func (k *KeysEndpoint) ListLabels(ctx context.Context, params ListLabelsParams, opts ...requester.Option) ([]Labels, PagingInfo, *http.Response, error) {
	results := FindListKeyLabelsResponse{}
	resp, _, err := k.ReceiveContext(ctx, &results,
		requester.Get(),
		k.KeyLabelsPath(),
		requester.QueryParams(params),
		optList(opts))
	return results.Labels, results.PagingInfo, resp, err
}

type optList []requester.Option

func (l optList) Apply(r *requester.Requester) error {
	return r.Apply(l...)
}*/
