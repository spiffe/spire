package akeylesskms

import (
	"context"
	"strings"
	"sync"

	"github.com/akeylesslabs/akeyless-go/v3"
	log "github.com/hashicorp/go-hclog"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/status"
)

type keyFetcher struct {
	log log.Logger
}

func (kf *keyFetcher) fetchKeyEntries(ctx context.Context) ([]*keyEntry, error) {
	var keyEntries []*keyEntry
	var keyEntriesMutex sync.Mutex

	body := akeyless.ListItems{}
	body.SetType([]string{pluginKeyType})
	body.SetTag(pluginKeyTag)
	body.SetToken(GetAuthToken())

	g, ctx := errgroup.WithContext(ctx)

	for {
		out, _, err := AklClient.ListItems(ctx).Body(body).Execute()
		if err != nil {
			return nil, err
		}
		if len(out.GetItems()) == 0 {
			break
		}

		kf.log.Info("found %v classic keys created by plugin", len(out.GetItems()))

		for _, ck := range out.GetItems() {
			if !ck.ItemGeneralInfo.HasClassicKeyDetails() {
				kf.log.Debug("Item %v retrieved as list of classic keys, doesn't have classic key details", ck.GetItemName())
				continue
			}
			keySpec := *ck.ItemGeneralInfo.GetClassicKeyDetails().KeyType
			keyType := keyTypeFromKeySpec(keySpec)
			if keyType == keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE {
				kf.log.Debug("Item %v retrieved as list of classic keys, have classic key type [%v] not supported by Spire", ck.GetItemName(), keySpec)
				continue
			}

			displayId := ck.GetDisplayId()
			spireKeyID := strings.TrimPrefix(ck.GetItemName(), "/")

			g.Go(func() error {
				entry, err := kf.fetchKeyEntryDetails(ctx, displayId, spireKeyID, keyType)
				if err != nil {
					return err
				}

				keyEntriesMutex.Lock()
				keyEntries = append(keyEntries, entry)
				keyEntriesMutex.Unlock()
				return nil
			})
		}

		if !out.HasNextPage() {
			break
		}
		body.SetPaginationToken(out.GetNextPage())
	}

	// wait for all the detail gathering routines to finish
	if err := g.Wait(); err != nil {
		statusErr := status.Convert(err)
		return nil, status.Errorf(statusErr.Code(), "failed to fetch keys: %v", statusErr.Message())
	}

	return keyEntries, nil
}

func (kf *keyFetcher) fetchKeyEntryDetails(ctx context.Context, keyDisplayId, keyID string, keyType keymanagerv1.KeyType) (*keyEntry, error) {
	publicKey, err := fetchPublicKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	pk := &keymanagerv1.PublicKey{
		Id:          keyID,
		Type:        keyType,
		PkixData:    publicKey,
		Fingerprint: makeFingerprint(publicKey),
	}

	return &keyEntry{DisplayId: keyDisplayId, PublicKey: pk}, nil
}
