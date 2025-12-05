package azurekeyvault

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/go-jose/go-jose/v4"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/keymanager/v1"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// keyVaultSignatureToASN1Encoded converts the signature format from IEEE P1363 to ASN.1/DER for ECDSA signed messages
// If the message is RSA signed, it's just returned i.e: no conversion needed for RSA signed messages
// This is all because when the signing algorithm used is ECDSA, azure's Sign API produces an IEEE P1363 format response
// while we expect the RFC3279 ASN.1 DER Format during signature verification (ecdsa.VerifyASN1).
func keyVaultSignatureToASN1Encoded(keyVaultSigResult []byte, keyType keymanagerv1.KeyType) ([]byte, error) {
	isRSA := keyType == keymanagerv1.KeyType_RSA_2048 || keyType == keymanagerv1.KeyType_RSA_4096
	if isRSA {
		// No conversion needed, it's already ASN.1 encoded
		return keyVaultSigResult, nil
	}
	sigLength := len(keyVaultSigResult)
	// The sig byte array length must either be 64 (ec-p256) or 96 (ec-p384)
	if sigLength != 64 && sigLength != 96 {
		return nil, status.Errorf(codes.Internal, "malformed signature response")
	}
	rVal := new(big.Int)
	rVal.SetBytes(keyVaultSigResult[0 : sigLength/2])
	sVal := new(big.Int)
	sVal.SetBytes(keyVaultSigResult[sigLength/2 : sigLength])
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(rVal)
		b.AddASN1BigInt(sVal)
	})
	return b.Bytes()
}

// keyVaultKeyToRawKey takes a *azkeys.JSONWebKey and returns the corresponding raw public key
// For example *ecdsa.PublicKey or *rsa.PublicKey etc
func keyVaultKeyToRawKey(keyVaultKey *azkeys.JSONWebKey) (any, error) {
	// Marshal the key to JSON
	jwkJSON, err := keyVaultKey.MarshalJSON()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal key: %v", err)
	}

	// Parse JWK
	var key jose.JSONWebKey
	if err := json.Unmarshal(jwkJSON, &key); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse key: %v", err)
	}

	if key.Key == nil {
		return nil, status.Errorf(codes.Internal, "failed to convert Key Vault key to raw key")
	}

	return key.Key, nil
}

func getCreateKeyParameters(keyType keymanagerv1.KeyType, keyTags map[string]*string) (*azkeys.CreateKeyParameters, error) {
	result := &azkeys.CreateKeyParameters{}
	switch keyType {
	case keymanagerv1.KeyType_RSA_2048:
		result.Kty = to.Ptr(azkeys.JSONWebKeyTypeRSA)
		result.KeySize = to.Ptr(int32(2048))
	case keymanagerv1.KeyType_RSA_4096:
		result.Kty = to.Ptr(azkeys.JSONWebKeyTypeRSA)
		result.KeySize = to.Ptr(int32(4096))
	case keymanagerv1.KeyType_EC_P256:
		result.Kty = to.Ptr(azkeys.JSONWebKeyTypeEC)
		result.Curve = to.Ptr(azkeys.JSONWebKeyCurveNameP256)
	case keymanagerv1.KeyType_EC_P384:
		result.Kty = to.Ptr(azkeys.JSONWebKeyTypeEC)
		result.Curve = to.Ptr(azkeys.JSONWebKeyCurveNameP384)
	default:
		return nil, status.Errorf(codes.Internal, "unsupported key type: %v", keyType)
	}
	// Specify the key operations as Sign and Verify
	result.KeyOps = append(result.KeyOps, to.Ptr(azkeys.JSONWebKeyOperationSign), to.Ptr(azkeys.JSONWebKeyOperationVerify))
	// Set the key tags
	result.Tags = keyTags
	return result, nil
}

func signingAlgorithmForKeyVault(keyType keymanagerv1.KeyType, signerOpts any) (azkeys.JSONWebKeySignatureAlgorithm, error) {
	var (
		hashAlgo keymanagerv1.HashAlgorithm
		isPSS    bool
	)

	switch opts := signerOpts.(type) {
	case *keymanagerv1.SignDataRequest_HashAlgorithm:
		hashAlgo = opts.HashAlgorithm
		isPSS = false
	case *keymanagerv1.SignDataRequest_PssOptions:
		if opts.PssOptions == nil {
			return "", errors.New("invalid signerOpts. PSS options are required")
		}
		hashAlgo = opts.PssOptions.HashAlgorithm
		isPSS = true
		// opts.PssOptions.SaltLength is handled by Key Vault. The salt length matches the bits of the hashing algorithm.
	default:
		return "", fmt.Errorf("unsupported signer opts type %T", opts)
	}

	isRSA := keyType == keymanagerv1.KeyType_RSA_2048 || keyType == keymanagerv1.KeyType_RSA_4096

	switch {
	case hashAlgo == keymanagerv1.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM:
		return "", errors.New("hash algorithm is required")
	case keyType == keymanagerv1.KeyType_EC_P256 && hashAlgo == keymanagerv1.HashAlgorithm_SHA256:
		return azkeys.JSONWebKeySignatureAlgorithmES256, nil
	case keyType == keymanagerv1.KeyType_EC_P384 && hashAlgo == keymanagerv1.HashAlgorithm_SHA384:
		return azkeys.JSONWebKeySignatureAlgorithmES384, nil
	case isRSA && !isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA256:
		return azkeys.JSONWebKeySignatureAlgorithmRS256, nil
	case isRSA && !isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA384:
		return azkeys.JSONWebKeySignatureAlgorithmRS384, nil
	case isRSA && !isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA512:
		return azkeys.JSONWebKeySignatureAlgorithmRS512, nil
	case isRSA && isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA256:
		return azkeys.JSONWebKeySignatureAlgorithmPS256, nil
	case isRSA && isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA384:
		return azkeys.JSONWebKeySignatureAlgorithmPS384, nil
	case isRSA && isPSS && hashAlgo == keymanagerv1.HashAlgorithm_SHA512:
		return azkeys.JSONWebKeySignatureAlgorithmPS512, nil
	default:
		return "", fmt.Errorf("unsupported combination of key type: %v and hashing algorithm: %v", keyType, hashAlgo)
	}
}
