package akeylesskms

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
)

func buildKeyName(keyId string, config *Config) string {
	//AkeylessTargetFolder ends with '/'
	domain := config.TrustDomain
	return fmt.Sprintf("%v%v/%v/%v", config.AkeylessTargetFolder, domain, config.ServerID, keyId)
}

func keySpecFromKeyType(keyType keymanagerv1.KeyType) string {
	switch keyType {
	case keymanagerv1.KeyType_RSA_2048:
		return "RSA2048"
	case keymanagerv1.KeyType_RSA_4096:
		return "RSA4096"
	case keymanagerv1.KeyType_EC_P256:
		return "EC256"
	case keymanagerv1.KeyType_EC_P384:
		return "EC384"
	default:
		return ""
	}
}

func keyTypeFromKeySpec(keySpec string) keymanagerv1.KeyType {
	switch keySpec {
	case "RSA2048":
		return keymanagerv1.KeyType_RSA_2048
	case "RSA4096":
		return keymanagerv1.KeyType_RSA_4096
	case "EC256":
		return keymanagerv1.KeyType_EC_P256
	case "EC384":
		return keymanagerv1.KeyType_EC_P384
	default:
		return keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE
	}
}

func makeFingerprint(pkixData []byte) string {
	s := sha256.Sum256(pkixData)
	return hex.EncodeToString(s[:])
}

func defineHashingAlgorithm(keyType keymanagerv1.KeyType, signerOpts interface{}) (string, error) {
	var hashAlgo keymanagerv1.HashAlgorithm
	switch opts := signerOpts.(type) {
	case *keymanagerv1.SignDataRequest_HashAlgorithm:
		hashAlgo = opts.HashAlgorithm
	case *keymanagerv1.SignDataRequest_PssOptions:
		if opts.PssOptions == nil {
			return "", errors.New("PSS options are required")
		}
		hashAlgo = opts.PssOptions.HashAlgorithm
	default:
		return "", fmt.Errorf("unsupported signer opts type %T", opts)
	}

	switch hashAlgo {
	case keymanagerv1.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM:
		return "", errors.New("hash algorithm is required")
	case keymanagerv1.HashAlgorithm_SHA256:
		return "SHA256", nil
	case keymanagerv1.HashAlgorithm_SHA384:
		return "SHA384", nil
	case keymanagerv1.HashAlgorithm_SHA512:
		return "SHA512", nil
	default:
		return "", fmt.Errorf("unsupported combination of keytype: %v and hashing algorithm: %v", keyType, hashAlgo)
	}
}
