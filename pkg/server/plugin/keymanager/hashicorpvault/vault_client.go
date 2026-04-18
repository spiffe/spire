package hashicorpvault

import (
	"encoding/pem"

	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// getKeyEntry converts a Vault transit key's raw data map into a keymanager keyEntry,
// parsing the public key and determining the SPIRE key type.
func getKeyEntry(keyName string, keyData map[string]any) (*keyEntry, error) {
	spireKeyID, ok := spireKeyIDFromKeyName(keyName)
	if !ok {
		return nil, status.Errorf(codes.Internal, "unable to get SPIRE key ID from key %s", keyName)
	}

	pk, ok := keyData["public_key"]
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

	pubKeyType, ok := keyData["name"]
	if !ok {
		return nil, status.Errorf(codes.Internal, "expected name to be present")
	}

	pubKeyTypeStr, ok := pubKeyType.(string)
	if !ok {
		return nil, status.Errorf(codes.Internal, "expected public key type to be of type %T but got %T", pubKeyTypeStr, pubKeyType)
	}

	var keyType keymanagerv1.KeyType

	switch pubKeyTypeStr {
	case "P-256":
		keyType = keymanagerv1.KeyType_EC_P256
	case "P-384":
		keyType = keymanagerv1.KeyType_EC_P384
	case "rsa-2048":
		keyType = keymanagerv1.KeyType_RSA_2048
	case "rsa-4096":
		keyType = keymanagerv1.KeyType_RSA_4096
	default:
		return nil, status.Errorf(codes.Internal, "unsupported key type: %v", pubKeyTypeStr)
	}

	return &keyEntry{
		KeyName: keyName,
		PublicKey: &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    pemBlock.Bytes,
			Fingerprint: makeFingerprint(pemBlock.Bytes),
		},
	}, nil
}

// spireKeyIDFromKeyName parses a Vault transit key name to get the
// SPIRE Key ID. This Key ID is used in the Server KeyManager interface.
func spireKeyIDFromKeyName(keyName string) (string, bool) {
	// A key name would have the format <UUID>-<SPIRE-KEY-ID>.
	// first we find the position where the SPIRE Key ID starts.
	spireKeyIDIndex := 37 // 36 is the UUID length plus one '-' separator
	if spireKeyIDIndex >= len(keyName) {
		// The index is out of range.
		return "", false
	}
	spireKeyID := keyName[spireKeyIDIndex:]
	return spireKeyID, true
}
