package hashicorpvault

import (
	"encoding/pem"

	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"github.com/spiffe/spire/pkg/server/common/vault"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// getKeyEntry converts a Vault transit KeyEntry into a keymanager keyEntry,
// parsing the public key and determining the SPIRE key type from the top-level Vault key type.
func getKeyEntry(ve *vault.KeyEntry) (*keyEntry, error) {
	spireKeyID, ok := spireKeyIDFromKeyName(ve.KeyName)
	if !ok {
		return nil, status.Errorf(codes.Internal, "unable to get SPIRE key ID from key %s", ve.KeyName)
	}

	pk, ok := ve.KeyData["public_key"]
	if !ok {
		return nil, status.Errorf(codes.Internal, "expected public key to be present")
	}

	pkStr, ok := pk.(string)
	if !ok {
		return nil, status.Errorf(codes.Internal, "expected public key data type %T but got %T", pkStr, pk)
	}

	pemBlock, _ := pem.Decode([]byte(pkStr))
	if pemBlock == nil || pemBlock.Type != "PUBLIC KEY" {
		return nil, status.Error(codes.Internal, "unable to decode PEM key")
	}

	var keyType keymanagerv1.KeyType
	switch ve.KeyType {
	case "ecdsa-p256":
		keyType = keymanagerv1.KeyType_EC_P256
	case "ecdsa-p384":
		keyType = keymanagerv1.KeyType_EC_P384
	case "rsa-2048":
		keyType = keymanagerv1.KeyType_RSA_2048
	case "rsa-4096":
		keyType = keymanagerv1.KeyType_RSA_4096
	default:
		return nil, status.Errorf(codes.Internal, "unsupported key type: %v", ve.KeyType)
	}

	return &keyEntry{
		KeyName: ve.KeyName,
		PublicKey: &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    pemBlock.Bytes,
			Fingerprint: makeFingerprint(pemBlock.Bytes),
		},
	}, nil
}

// uuidStringLength is the length of a UUID string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
const uuidStringLength = 36

// spireKeyIDFromKeyName parses a Vault transit key name to get the
// SPIRE Key ID. This Key ID is used in the Server KeyManager interface.
// Key names have the format <UUID>-<SPIRE-KEY-ID>.
func spireKeyIDFromKeyName(keyName string) (string, bool) {
	if len(keyName) <= uuidStringLength+1 || keyName[uuidStringLength] != '-' {
		return "", false
	}
	return keyName[uuidStringLength+1:], true
}
