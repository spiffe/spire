package hashicorpvault

import (
	"encoding/pem"
	"strings"
	"time"

	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"github.com/spiffe/spire/pkg/server/common/vault"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// uuidStringLength is the length of a UUID string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
const uuidStringLength = 36

// getKeyEntry converts a Vault transit KeyEntry into a keymanager keyEntry,
// parsing the public key and determining the SPIRE key type from the top-level
// Vault key type. Returns (nil, false, nil) if the key belongs to a different
// server instance (i.e. the key name does not match the expected serverID prefix).
func getKeyEntry(ve *vault.KeyEntry, serverID string) (*keyEntry, bool, error) {
	spireKeyID, ok := spireKeyIDFromKeyName(ve.KeyName, serverID)
	if !ok {
		return nil, false, nil
	}

	pk, ok := ve.KeyData["public_key"]
	if !ok {
		return nil, false, status.Errorf(codes.Internal, "expected public key to be present")
	}

	pkStr, ok := pk.(string)
	if !ok {
		return nil, false, status.Errorf(codes.Internal, "expected public key data type %T but got %T", pkStr, pk)
	}

	pemBlock, _ := pem.Decode([]byte(pkStr))
	if pemBlock == nil || pemBlock.Type != "PUBLIC KEY" {
		return nil, false, status.Error(codes.Internal, "unable to decode PEM key")
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
		return nil, false, status.Errorf(codes.Internal, "unsupported key type: %v", ve.KeyType)
	}

	return &keyEntry{
		KeyName: ve.KeyName,
		PublicKey: &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    pemBlock.Bytes,
			Fingerprint: makeFingerprint(pemBlock.Bytes),
		},
	}, true, nil
}

// parseKeyCreationTime extracts and parses the creation_time field from Vault key data.
func parseKeyCreationTime(keyData map[string]any) (time.Time, error) {
	ct, ok := keyData["creation_time"]
	if !ok {
		return time.Time{}, status.Error(codes.Internal, "key data is missing creation_time")
	}
	ctStr, ok := ct.(string)
	if !ok {
		return time.Time{}, status.Errorf(codes.Internal, "expected creation_time type string but got %T", ct)
	}
	t, err := time.Parse(time.RFC3339Nano, ctStr)
	if err != nil {
		return time.Time{}, status.Errorf(codes.Internal, "failed to parse creation_time %q: %v", ctStr, err)
	}
	return t, nil
}

// spireKeyIDFromKeyName parses a Vault transit key name to extract the SPIRE Key ID.
// Key names have the format <SERVER-ID>-<UUID>-<SPIRE-KEY-ID>.
// Returns ("", false) if the key name does not match the expected serverID prefix or format.
func spireKeyIDFromKeyName(keyName, serverID string) (string, bool) {
	prefix := serverID + "-"
	if !strings.HasPrefix(keyName, prefix) {
		return "", false
	}
	rest := keyName[len(prefix):]
	// rest must be at least "<UUID>-<one-char-spireKeyID>"
	if len(rest) <= uuidStringLength+1 || rest[uuidStringLength] != '-' {
		return "", false
	}
	return rest[uuidStringLength+1:], true
}
