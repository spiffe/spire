package azurekeyvault

import (
	"context"
	"crypto/x509"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/aws/smithy-go/ptr"
	"github.com/hashicorp/go-hclog"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type keyFetcher struct {
	keyVaultClient cloudKeyManagementService
	log            hclog.Logger
	serverID       string
	trustDomain    string
}

// fetchKeyEntries requests Key Vault to get the list of keys that are
// active in this server. They are returned as a keyEntry array.
func (kf *keyFetcher) fetchKeyEntries(ctx context.Context) ([]*keyEntry, error) {
	var keyEntries []*keyEntry
	var keyEntriesMutex sync.Mutex
	g, ctx := errgroup.WithContext(ctx)

	// List all the key from the configured key vault URL
	pager := kf.keyVaultClient.NewListKeysPager(nil)

	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed while listing keys: %v", err)
		}
		for _, key := range resp.Value {
			// Skip keys that do not belong this server
			belongsToServer := kf.keyBelongsToServer(key)
			if !belongsToServer {
				continue
			}

			spireKeyID, ok := spireKeyIDFromKeyName(key.KID.Name())
			if !ok {
				kf.log.Warn("Could not get SPIRE Key ID from key", keyNameTag, key.KID.Name())
				continue
			}

			k := key
			// trigger a goroutine to get the details of the key
			g.Go(func() error {
				entry, err := kf.fetchKeyEntryDetails(ctx, k, spireKeyID)
				if err != nil {
					return err
				}

				keyEntriesMutex.Lock()
				keyEntries = append(keyEntries, entry)
				keyEntriesMutex.Unlock()
				return nil
			})
		}
	}

	// Wait for all the detail gathering routines to finish.
	if err := g.Wait(); err != nil {
		statusErr := status.Convert(err)
		return nil, status.Errorf(statusErr.Code(), "failed to fetch key entry details: %v", statusErr.Message())
	}

	return keyEntries, nil
}

func (kf *keyFetcher) keyBelongsToServer(key *azkeys.KeyItem) bool {
	trustDomain, hasTD := key.Tags[tagNameServerTrustDomain]
	serverID, hasServerID := key.Tags[tagNameServerID]
	return hasTD && hasServerID && *trustDomain == kf.trustDomain && *serverID == kf.serverID
}

func (kf *keyFetcher) fetchKeyEntryDetails(ctx context.Context, keyItem *azkeys.KeyItem, spireKeyID string) (*keyEntry, error) {
	if keyItem == nil {
		return nil, status.Error(codes.Internal, "keyItem is nil")
	}

	getKeyResponse, err := kf.keyVaultClient.GetKey(ctx, keyItem.KID.Name(), keyItem.KID.Version(), nil)

	switch {
	case err != nil:
		return nil, status.Errorf(codes.Internal, "failed to fetch key details: %v", err)
	case getKeyResponse.KeyBundle.Attributes == nil:
		return nil, status.Error(codes.Internal, "malformed get key response")
	case !ptr.ToBool(getKeyResponse.KeyBundle.Attributes.Enabled):
		// this means something external to the plugin, disabled the key
		// returning an error provides the opportunity of reverting this in azure key vault
		return nil, status.Errorf(codes.FailedPrecondition, "found disabled SPIRE key: %q, name: %q", *getKeyResponse.Key.KID, getKeyResponse.Key.KID.Name())
	}

	keyType, ok := keyTypeFromKeySpec(getKeyResponse.KeyBundle)
	if !ok {
		return nil, status.Errorf(codes.Internal, "unsupported key spec: %v", *getKeyResponse.KeyBundle.Key)
	}

	rawkey, err := keyVaultKeyToRawKey(getKeyResponse.Key)
	if err != nil {
		return nil, err
	}
	publicKey, err := x509.MarshalPKIXPublicKey(rawkey)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal public key: %v", err)
	}

	return &keyEntry{
		KeyID:      string(*getKeyResponse.Key.KID),
		KeyName:    getKeyResponse.Key.KID.Name(),
		keyVersion: getKeyResponse.Key.KID.Version(),
		PublicKey: &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    publicKey,
			Fingerprint: makeFingerprint(publicKey),
		},
	}, nil
}

func keyTypeFromKeySpec(keyBundle azkeys.KeyBundle) (keymanagerv1.KeyType, bool) {
	switch {
	case *keyBundle.Key.Kty == azkeys.JSONWebKeyTypeRSA && len(keyBundle.Key.N) == 256:
		return keymanagerv1.KeyType_RSA_2048, true
	case *keyBundle.Key.Kty == azkeys.JSONWebKeyTypeRSA && len(keyBundle.Key.N) == 512:
		return keymanagerv1.KeyType_RSA_4096, true
	case *keyBundle.Key.Kty == azkeys.JSONWebKeyTypeEC && *keyBundle.Key.Crv == azkeys.JSONWebKeyCurveNameP256:
		return keymanagerv1.KeyType_EC_P256, true
	case *keyBundle.Key.Kty == azkeys.JSONWebKeyTypeEC && *keyBundle.Key.Crv == azkeys.JSONWebKeyCurveNameP384:
		return keymanagerv1.KeyType_EC_P384, true

	default:
		return keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE, false
	}
}

// spireKeyIDFromKeyName parses a Key Vault key name to get the
// SPIRE Key ID. This Key ID is used in the Server KeyManager interface.
func spireKeyIDFromKeyName(keyName string) (string, bool) {
	// A key name would have the format spire-key-${UUID}-x509-CA-A.
	// first we find the position where the SPIRE Key ID starts.
	// For that, we need to add the length of the key name prefix that we
	// are using, the UUID length, and the two "-" separators used in our format.
	spireKeyIDIndex := len(keyNamePrefix) + 38 // 39 is the UUID length plus two '-' separators
	if spireKeyIDIndex >= len(keyName) {
		// The index is out of range.
		return "", false
	}
	spireKeyID := keyName[spireKeyIDIndex:]
	return spireKeyID, true
}
