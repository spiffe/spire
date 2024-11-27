package keyvaluestore

import (
	"context"
	"errors"
	"time"

	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/protoutil"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/keyvalue"
	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/record"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// AppendBundle append bundle contents to the existing bundle (by trust domain). If no existing one is present, create it.
func (ds *DataStore) AppendBundle(ctx context.Context, appends *common.Bundle) (*common.Bundle, error) {
	if appends == nil {
		return nil, kvError.New("missing bundle in request")
	}

	existing, err := ds.bundles.Get(ctx, appends.TrustDomainId)
	switch {
	case err == nil:
		if merged, changed := bundleutil.MergeBundles(existing.Object.Bundle, appends); changed {
			merged.SequenceNumber++
			if err := ds.bundles.Update(ctx, bundleObject{Bundle: merged}, existing.Metadata.Revision); err != nil {
				return nil, dsErr(err, "failed to update existing bundle on append")
			}
			return merged, nil
		} else {
			// Bundle didn't change. Return the original.
			return existing.Object.Bundle, nil
		}
	case errors.Is(err, record.ErrNotFound):
		if err := ds.bundles.Create(ctx, bundleObject{Bundle: appends}); err != nil {
			return nil, dsErr(err, "failed to create new bundle on append")
		}
		return appends, nil
	default:
		return nil, dsErr(err, "failed to fetch existing bundle on append")
	}
}

// CountBundles can be used to count all existing bundles.
func (ds *DataStore) CountBundles(ctx context.Context) (int32, error) {
	records, _, err := ds.bundles.List(ctx, &datastore.ListBundlesRequest{})

	if err != nil {
		return 0, err
	}

	return int32(len(records)), nil
}

// CreateBundle stores the given bundle
func (ds *DataStore) CreateBundle(ctx context.Context, in *common.Bundle) (*common.Bundle, error) {
	if err := ds.bundles.Create(ctx, bundleObject{Bundle: in}); err != nil {
		return nil, dsErr(err, "failed to create bundle")
	}
	return in, nil
}

// DeleteBundle deletes the bundle with the matching TrustDomain. Any CACert data passed is ignored.
func (ds *DataStore) DeleteBundle(ctx context.Context, trustDomainID string, mode datastore.DeleteMode) error {
	_, err := ds.FetchBundle(ctx, trustDomainID)
	if err != nil {
		return kvError.Wrap(err)
	}

	entriesAssociation, _, err := ds.entries.List(ctx, &listRegistrationEntries{
		ListRegistrationEntriesRequest: datastore.ListRegistrationEntriesRequest{
			ByFederatesWith: &datastore.ByFederatesWith{
				TrustDomains: []string{trustDomainID},
				Match:        datastore.MatchAny,
			},
		},
	})

	if err != nil {
		return kvError.Wrap(err)
	}
	entriesCount := len(entriesAssociation)

	var errCount int
	var firstErr error

	if entriesCount > 0 {
		switch mode {
		case datastore.Delete:
			if err := ds.bundles.Delete(ctx, trustDomainID); err != nil {
				return dsErr(err, "datastore-keyvalue")
			}

			// TODO: Should be done using batch.

			for _, record := range entriesAssociation {
				entry := record.Object.Entry
				if err := ds.entries.Delete(ctx, entry.EntryId); err != nil {
					if firstErr == nil {
						firstErr = err
					}
					errCount++
				}
			}
		case datastore.Dissociate:
			if err := ds.bundles.Delete(ctx, trustDomainID); err != nil {
				return dsErr(err, "datastore-keyvalue")
			}

			// TODO: Should be done using batch.

			for _, record := range entriesAssociation {
				record.Object.Entry.FederatesWith = removeFirstOccurrence(record.Object.Entry.FederatesWith, trustDomainID)
				if err := ds.entries.Update(ctx, record.Object, record.Metadata.Revision); err != nil {
					if firstErr == nil {
						firstErr = err
					}
					errCount++
				}
			}
		default:
			dsError := dsErr(err, "failed to delete bundle")
			return status.Newf(codes.FailedPrecondition, "datastore-keyvalue: cannot delete bundle; federated with %d registration entries: %v", entriesCount, dsError).Err()
		}
	} else {
		if err := ds.bundles.Delete(ctx, trustDomainID); err != nil {
			return dsErr(err, "datastore-keyvalue")
		}
	}

	if firstErr != nil {
		return dsErr(firstErr, "failed to delete %d of %d bundle associated entries: first error:", errCount, entriesCount)
	}

	return nil
}

func removeFirstOccurrence(slice []string, element string) []string {
	for i, v := range slice {
		if v == element {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

// FetchBundle returns the bundle matching the specified Trust Domain.
func (ds *DataStore) FetchBundle(ctx context.Context, trustDomainID string) (*common.Bundle, error) {
	out, err := ds.bundles.Get(ctx, trustDomainID)
	switch {
	case err == nil:
		return out.Object.Bundle, nil
	case errors.Is(err, record.ErrNotFound):
		return nil, nil
	default:
		return nil, dsErr(err, "failed to fetch bundle")
	}
}

// ListBundles can be used to fetch all existing bundles.
func (ds *DataStore) ListBundles(ctx context.Context, req *datastore.ListBundlesRequest) (*datastore.ListBundlesResponse, error) {
	records, cursor, err := ds.bundles.List(ctx, req)
	if err != nil {
		return nil, err
	}
	resp := &datastore.ListBundlesResponse{
		Pagination: newPagination(req.Pagination, cursor),
	}
	resp.Bundles = make([]*common.Bundle, 0, len(records))
	for _, record := range records {
		resp.Bundles = append(resp.Bundles, record.Object.Bundle)
	}
	return resp, nil
}

// PruneBundle removes expired certs and keys from a bundle
func (ds *DataStore) PruneBundle(ctx context.Context, trustDomainID string, expiresBefore time.Time) (changed bool, err error) {
	r, err := ds.bundles.Get(ctx, trustDomainID)
	switch {
	case err == nil:
		pruned, changed, err := bundleutil.PruneBundle(r.Object.Bundle, expiresBefore, ds.log)
		switch {
		case err != nil:
			return false, status.Errorf(codes.Unknown, "prune failed: %v", err)
		case changed:
			pruned.SequenceNumber = r.Object.Bundle.SequenceNumber + 1
			if err := ds.bundles.Update(ctx, bundleObject{Bundle: pruned}, r.Metadata.Revision); err != nil {
				return false, dsErr(err, "failed to update existing bundle on prune")
			}
			return true, nil
		default:
			return false, nil
		}
	case errors.Is(err, record.ErrNotFound):
		return false, nil
	default:
		return false, dsErr(err, "failed to fetch existing bundle on prune")
	}
}

// SetBundle sets bundle contents. If no bundle exists for the trust domain, it is created.
func (ds *DataStore) SetBundle(ctx context.Context, in *common.Bundle) (*common.Bundle, error) {
	bundle, err := ds.bundles.Get(ctx, in.TrustDomainId)
	switch {
	case err == nil:
		if err := ds.bundles.Update(ctx, bundleObject{Bundle: in}, bundle.Metadata.Revision); err != nil {
			return nil, dsErr(err, "failed to update bundle on set")
		}
		return in, nil
	case errors.Is(err, record.ErrNotFound):
		if err := ds.bundles.Create(ctx, bundleObject{Bundle: in}); err != nil {
			return nil, dsErr(err, "failed to create bundle on set")
		}
		return in, nil
	default:
		return nil, dsErr(err, "failed to fetch bundle for set")
	}
}

// UpdateBundle updates an existing bundle with the given CAs. Overwrites any
// existing certificates.
func (ds *DataStore) UpdateBundle(ctx context.Context, newBundle *common.Bundle, mask *common.BundleMask) (*common.Bundle, error) {
	existing, err := ds.bundles.Get(ctx, newBundle.TrustDomainId)
	if err != nil {
		return nil, dsErr(err, "datastore-keyvalue")
	}

	updated := existing.Object

	if mask == nil {
		mask = protoutil.AllTrueCommonBundleMask
	}
	if mask.RefreshHint {
		updated.Bundle.RefreshHint = newBundle.RefreshHint
	}
	if mask.RootCas {
		updated.Bundle.RootCas = newBundle.RootCas
	}
	if mask.JwtSigningKeys {
		updated.Bundle.JwtSigningKeys = newBundle.JwtSigningKeys
	}
	if mask.SequenceNumber {
		updated.Bundle.SequenceNumber = newBundle.SequenceNumber
	}

	if err := ds.bundles.Update(ctx, updated, existing.Metadata.Revision); err != nil {
		return nil, dsErr(err, "datastore-keyvalue")
	}
	return updated.Bundle, nil
}

type bundleObject struct {
	Bundle *common.Bundle
}

func (o bundleObject) Key() string {
	if o.Bundle == nil {
		return ""
	}
	return o.Bundle.TrustDomainId
}

type bundleCodec struct{}

func (bundleCodec) Marshal(o *bundleObject) (string, []byte, error) {
	data, err := proto.Marshal(o.Bundle)
	if err != nil {
		return "", nil, err
	}
	return o.Key(), data, nil
}

func (bundleCodec) Unmarshal(in []byte, out *bundleObject) error {
	bundle := new(common.Bundle)
	if err := proto.Unmarshal(in, bundle); err != nil {
		return err
	}
	out.Bundle = bundle
	return nil
}

type bundleIndex struct {
}

func (c *bundleIndex) SetUp() {
}

func (c *bundleIndex) Get(obj *record.Record[bundleObject]) {

}

func (c *bundleIndex) List(req *datastore.ListBundlesRequest) (*keyvalue.ListObject, error) {
	cursor, limit, err := getPaginationParams(req.Pagination)
	if err != nil {
		return nil, err
	}

	list := new(keyvalue.ListObject)

	list.Cursor = cursor
	list.Limit = limit

	return list, nil
}
