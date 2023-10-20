package ciphertrustkms

import (
	"context"
	"strconv"
	"sync"

	"github.com/hashicorp/go-hclog"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type keyFetcher struct {
	kmsClientCipherTrust cloudKeyManagementServiceCipherTrust
	log                  hclog.Logger
	serverID             string
	tdHash               string
}

// fetchKeyEntries requests Cloud KMS to get the list of CryptoKeys that are
// active in this server. They are returned as a keyEntry array.
func (kf *keyFetcher) fetchKeyEntriesCipherTrust(ctx context.Context) ([]*keyEntryCipherTrust, error) {
	var keyEntriesCipherTrust []*keyEntryCipherTrust
	var keyEntriesMutex sync.Mutex
	g, ctx := errgroup.WithContext(ctx)

	labels := "&labels=" + labelNameServerTD + "=" + kf.tdHash + "," + labelNameServerID + "=" + kf.serverID + "," + labelNameActive + "=true"
	keys, err := kf.kmsClientCipherTrust.ListCryptoKeysCipherTrust(ctx, labels)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list SPIRE Server keys in Cloud KMS: %v", err)

	}
	it := keys.createKeyIterator()

	for {
		cryptoKey, ok := it.getNext()
		if !ok {
			break
		}
		if cryptoKey.ObjectType == "Public Key" {
			continue
		}

		spireKeyID, ok := getSPIREKeyIDFromCryptoKeyNameCipherTrust(cryptoKey.Name)
		if !ok {
			kf.log.Warn("Could not get SPIRE Key ID from CryptoKey", cryptoKeyNameTag, cryptoKey.Name)
			continue
		}
		kf.log.Debug(spireKeyID)
		kf.log.Debug(cryptoKey.Name)
		kf.log.Debug(cryptoKey.KeyID)

		// Trigger a goroutine to get the details of the key
		g.Go(func() error {
			entries, _ := kf.getKeyEntriesFromCryptoKeyCipherTrust(ctx, cryptoKey, spireKeyID)
			if err != nil {
				return err
			}
			if entries == nil {
				return nil
			}

			keyEntriesMutex.Lock()
			keyEntriesCipherTrust = append(keyEntriesCipherTrust, entries...)
			keyEntriesMutex.Unlock()
			return nil
		})

	}
	// Wait for all the detail gathering routines to finish.
	if err := g.Wait(); err != nil {
		statusErr := status.Convert(err)
		return nil, status.Errorf(statusErr.Code(), "failed to fetch entries: %v", statusErr.Message())
	}

	return keyEntriesCipherTrust, nil
}

// getKeyEntriesFromCryptoKey builds an array of keyEntry values from the provided
// CryptoKey. In order to do that, Cloud KMS is requested to list the
// CryptoKeyVersions of the CryptoKey. The public key of the CryptoKeyVersion is
// also retrieved from each CryptoKey to construct each keyEntry.
func (kf *keyFetcher) getKeyEntriesFromCryptoKeyCipherTrust(ctx context.Context, cryptoKey *Key, spireKeyID string) (keyEntries []*keyEntryCipherTrust, err error) {
	if cryptoKey == nil {
		return nil, status.Error(codes.Internal, "cryptoKey is nil")
	}

	keyType, ok := keyTypeFromCryptoKeyVersionAlgorithmCipherTrust(cryptoKey.CurveID)
	if !ok {
		return nil, status.Errorf(codes.Internal, "unsupported CryptoKeyVersionAlgorithm: %v", cryptoKey.CurveID)
	}
	pubKey, err := getPublicKeyFromCryptoKeyVersionCipherTrust(ctx, kf.log, kf.kmsClientCipherTrust, cryptoKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error getting public key: %v", err)
	}

	keyEntry := &keyEntryCipherTrust{
		cryptoKey:            cryptoKey,
		cryptoKeyVersionName: cryptoKey.Name + "/cryptoKeyVersions/" + strconv.Itoa(cryptoKey.Version),
		publicKey: &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    pubKey,
			Fingerprint: makeFingerprint(pubKey),
		},
	}

	keyEntries = append(keyEntries, keyEntry)
	//}

	return keyEntries, nil
}

// getSPIREKeyIDFromCryptoKeyName parses a CryptoKey resource name to get the
// SPIRE Key ID. This Key ID is used in the Server KeyManager interface.
func getSPIREKeyIDFromCryptoKeyNameCipherTrust(cryptoKeyName string) (string, bool) {
	// Get the last element of the path.
	i := 0

	// The i index will indicate us where
	// "spire-key-1f2e225a-91d8-4589-a4fe-f88b7bb04bac-x509-CA-A" starts.
	// Now we have to get the position where the SPIRE Key ID starts.
	// For that, we need to add the length of the CryptoKey name prefix that we
	// are using, the UUID length, and the two "-" separators used in our format.
	spireKeyIDIndex := i + len(cryptoKeyNamePrefix) + 38 // 38 is the UUID length plus two '-' separators
	if spireKeyIDIndex >= len(cryptoKeyName) {
		// The index is out of range.
		return "", false
	}
	spireKeyID := cryptoKeyName[spireKeyIDIndex:]
	return spireKeyID, true
}

// keyTypeFromCryptoKeyVersionAlgorithm gets the KeyType that corresponds to the
// given algo string
func keyTypeFromCryptoKeyVersionAlgorithmCipherTrust(algorithm string) (keymanagerv1.KeyType, bool) {
	switch algorithm {
	//code definition in a structure that matches the same name and the same value
	case "prime256v1":
		return keymanagerv1.KeyType_EC_P256, true
	default:
		return keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE, false
	}
}
