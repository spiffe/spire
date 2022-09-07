package gcpkms

import (
	"context"
	"encoding/pem"
	"errors"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/iterator"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type keyFetcher struct {
	keyRing        string
	kmsClient      kmsClient
	listCryptoKeys listCryptoKeysFn
	log            hclog.Logger
	serverID       string
	tdHash         string
}

// fetchKeyEntries requests Cloud KMS to get the list of CryptoKeys that are
// active in this server. They are returned as a keyEntry array.
func (kf *keyFetcher) fetchKeyEntries(ctx context.Context) ([]*keyEntry, error) {
	var keyEntries []*keyEntry
	var keyEntriesMutex sync.Mutex
	g, ctx := errgroup.WithContext(ctx)

	it := kf.listCryptoKeys(ctx, kf.kmsClient, &kmspb.ListCryptoKeysRequest{
		Parent: kf.keyRing,
		Filter: "labels.spire-server-td = " + kf.tdHash +
			" AND labels.spire-server-id = " + kf.serverID +
			" AND labels.spire-active = true",
	})
	for {
		cryptoKey, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to list SPIRE Server keys in Cloud KMS: %v", err)
		}
		spireKeyID, ok := kf.getSPIREKeyIDFromCryptoKeyName(cryptoKey.Name)
		if !ok {
			return nil, status.Errorf(codes.Internal, "could not get SPIRE Key ID from CryptoKey %q", cryptoKey.Name)
		}

		// Trigger a goroutine to get the details of the key
		g.Go(func() error {
			entry, err := kf.buildKeyEntryFromCryptoKey(ctx, cryptoKey, spireKeyID)
			if err != nil {
				return err
			}
			if entry == nil {
				return nil
			}

			keyEntriesMutex.Lock()
			keyEntries = append(keyEntries, entry)
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

// buildKeyEntryFromCryptoKey builds a keyEntry from the provided CryptoKey.
// In order to do that, Cloud KMS is requested to get the first CryptoKeyVersion
// of the CryptoKey. The public key of the CryptoKeyVersion is also retrieved to
// construct the returned keyEntry.
func (kf *keyFetcher) buildKeyEntryFromCryptoKey(ctx context.Context, cryptoKey *kmspb.CryptoKey, spireKeyID string) (*keyEntry, error) {
	if cryptoKey == nil {
		return nil, status.Error(codes.Internal, "cryptoKey is nil")
	}

	cryptoKeyVersion, err := kf.kmsClient.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{
		Name: cryptoKey.Name + "/cryptoKeyVersions/1",
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get CryptoKeyVersion: %v", err)
	}

	if cryptoKeyVersion.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, nil
	}

	keyType, ok := keyTypeFromCryptoKeyVersionAlgorithm(cryptoKeyVersion.Algorithm)
	if !ok {
		return nil, status.Errorf(codes.Internal, "unsupported CryptoKeyVersionAlgorithm: %v", cryptoKeyVersion.Algorithm)
	}

	kmsPublicKey, err := kf.kmsClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: cryptoKeyVersion.Name})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get public key: %v", err)
	}
	pemBlock, _ := pem.Decode([]byte(kmsPublicKey.Pem))

	return &keyEntry{
		cryptoKey:        cryptoKey,
		cryptoKeyVersion: cryptoKeyVersion,
		publicKey: &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    pemBlock.Bytes,
			Fingerprint: makeFingerprint(pemBlock.Bytes),
		},
	}, nil
}

// getSPIREKeyIDFromCryptoKeyName parses a CryptoKey resource name to get the
// SPIRE Key ID. This Key ID is used in the Server KeyManager interface.
func (kf *keyFetcher) getSPIREKeyIDFromCryptoKeyName(cryptoKeyName string) (string, bool) {
	i := strings.LastIndex(cryptoKeyName, "/")
	if i < 0 {
		// All CryptoKeys are under a Key Ring; not a valid Crypto Key name.
		return "", false
	}
	spireKeyIDIndex := i + len("spire-key") + 3 + 36
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
