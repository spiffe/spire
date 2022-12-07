package gcpkms

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/hashicorp/go-hclog"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type keyFetcher struct {
	keyRing   string
	kmsClient cloudKeyManagementService
	log       hclog.Logger
	serverID  string
	tdHash    string
}

// fetchKeyEntries requests Cloud KMS to get the list of CryptoKeys that are
// active in this server. They are returned as a keyEntry array.
func (kf *keyFetcher) fetchKeyEntries(ctx context.Context) ([]*keyEntry, error) {
	var keyEntries []*keyEntry
	var keyEntriesMutex sync.Mutex
	g, ctx := errgroup.WithContext(ctx)

	it := kf.kmsClient.ListCryptoKeys(ctx, &kmspb.ListCryptoKeysRequest{
		Parent: kf.keyRing,
		Filter: fmt.Sprintf("labels.%s = %s AND labels.%s = %s AND labels.%s = true",
			labelNameServerTD, kf.tdHash, labelNameServerID, kf.serverID, labelNameActive),
	})
	for {
		cryptoKey, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to list SPIRE Server keys in Cloud KMS: %v", err)
		}
		spireKeyID, ok := getSPIREKeyIDFromCryptoKeyName(cryptoKey.Name)
		if !ok {
			kf.log.Warn("Could not get SPIRE Key ID from CryptoKey", cryptoKeyNameTag, cryptoKey.Name)
			continue
		}

		// Trigger a goroutine to get the details of the key
		g.Go(func() error {
			entries, err := kf.getKeyEntriesFromCryptoKey(ctx, cryptoKey, spireKeyID)
			if err != nil {
				return err
			}
			if entries == nil {
				return nil
			}

			keyEntriesMutex.Lock()
			keyEntries = append(keyEntries, entries...)
			keyEntriesMutex.Unlock()
			return nil
		})
	}

	// Wait for all the detail gathering routines to finish.
	if err := g.Wait(); err != nil {
		statusErr := status.Convert(err)
		return nil, status.Errorf(statusErr.Code(), "failed to fetch entries: %v", statusErr.Message())
	}

	return keyEntries, nil
}

// getKeyEntriesFromCryptoKey builds an array of keyEntry values from the provided
// CryptoKey. In order to do that, Cloud KMS is requested to list the
// CryptoKeyVersions of the CryptoKey. The public key of the CryptoKeyVersion is
// also retrieved from each CryptoKey to construct each keyEntry.
func (kf *keyFetcher) getKeyEntriesFromCryptoKey(ctx context.Context, cryptoKey *kmspb.CryptoKey, spireKeyID string) (keyEntries []*keyEntry, err error) {
	if cryptoKey == nil {
		return nil, status.Error(codes.Internal, "cryptoKey is nil")
	}

	it := kf.kmsClient.ListCryptoKeyVersions(ctx, &kmspb.ListCryptoKeyVersionsRequest{
		Parent: cryptoKey.Name,
		// Filter by state, so only enabled keys are returned. This will leave
		// out all the versions that have been rotated.
		Filter: "state = " + kmspb.CryptoKeyVersion_ENABLED.String(),
	})
	for {
		cryptoKeyVersion, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failure listing CryptoKeyVersions: %v", err)
		}
		keyType, ok := keyTypeFromCryptoKeyVersionAlgorithm(cryptoKeyVersion.Algorithm)
		if !ok {
			return nil, status.Errorf(codes.Internal, "unsupported CryptoKeyVersionAlgorithm: %v", cryptoKeyVersion.Algorithm)
		}

		pubKey, err := getPublicKeyFromCryptoKeyVersion(ctx, kf.log, kf.kmsClient, cryptoKeyVersion.Name)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "error getting public key: %v", err)
		}

		keyEntry := &keyEntry{
			cryptoKey:            cryptoKey,
			cryptoKeyVersionName: cryptoKeyVersion.Name,
			publicKey: &keymanagerv1.PublicKey{
				Id:          spireKeyID,
				Type:        keyType,
				PkixData:    pubKey,
				Fingerprint: makeFingerprint(pubKey),
			},
		}

		keyEntries = append(keyEntries, keyEntry)
	}

	return keyEntries, nil
}

// getSPIREKeyIDFromCryptoKeyName parses a CryptoKey resource name to get the
// SPIRE Key ID. This Key ID is used in the Server KeyManager interface.
func getSPIREKeyIDFromCryptoKeyName(cryptoKeyName string) (string, bool) {
	// cryptoKeyName is the resource name for the CryptoKey holding the SPIRE Key
	// in the format: projects/*/locations/*/keyRings/*/cryptoKeys/spire-key-*-*.
	// Example: projects/project-name/locations/us-east1/keyRings/key-ring-name/cryptoKeys/spire-key-1f2e225a-91d8-4589-a4fe-f88b7bb04bac-x509-CA-A

	// Get the last element of the path.
	i := strings.LastIndex(cryptoKeyName, "/")
	if i < 0 {
		// All CryptoKeys are under a Key Ring; not a valid Crypto Key name.
		return "", false
	}

	// The i index will indicate us where
	// "spire-key-1f2e225a-91d8-4589-a4fe-f88b7bb04bac-x509-CA-A" starts.
	// Now we have to get the position where the SPIRE Key ID starts.
	// For that, we need to add the length of the CryptoKey name prefix that we
	// are using, the UUID length, and the two "-" separators used in our format.
	spireKeyIDIndex := i + len(cryptoKeyNamePrefix) + 39 // 39 is the UUID length plus two '-' separators
	if spireKeyIDIndex >= len(cryptoKeyName) {
		// The index is out of range.
		return "", false
	}
	spireKeyID := cryptoKeyName[spireKeyIDIndex:]
	return spireKeyID, true
}

// keyTypeFromCryptoKeyVersionAlgorithm gets the KeyType that corresponds to the
// given CryptoKeyVersion_CryptoKeyVersionAlgorithm.
func keyTypeFromCryptoKeyVersionAlgorithm(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (keymanagerv1.KeyType, bool) {
	switch algorithm {
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		return keymanagerv1.KeyType_EC_P256, true
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		return keymanagerv1.KeyType_EC_P384, true
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256:
		return keymanagerv1.KeyType_RSA_2048, true
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256:
		return keymanagerv1.KeyType_RSA_4096, true
	default:
		return keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE, false
	}
}
