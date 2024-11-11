package keyvaluestore

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/keyvalue"
	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/record"
)

func (ds *DataStore) CreateJoinToken(ctx context.Context, token *datastore.JoinToken) error {
	if token == nil || token.Token == "" || token.Expiry.IsZero() {
		return errors.New("token and expiry are required")
	}

	if err := ds.joinTokens.Create(ctx, joinTokenObject{JoinToken: token}); err != nil {
		return dsErr(err, "failed to create entry")
	}
	return nil
}

func (ds *DataStore) DeleteJoinToken(ctx context.Context, token string) error {
	return ds.joinTokens.Delete(ctx, token)
}

func (ds *DataStore) FetchJoinToken(ctx context.Context, token string) (*datastore.JoinToken, error) {
	out, err := ds.joinTokens.Get(ctx, token)
	switch {
	case err == nil:
		return out.Object.JoinToken, nil
	case errors.Is(err, record.ErrNotFound):
		return nil, nil
	default:
		return nil, dsErr(err, "failed to fetch join token relationship")
	}
}

func (ds *DataStore) PruneJoinTokens(ctx context.Context, expiresBefore time.Time) error {
	records, _, err := ds.joinTokens.List(ctx, &listJoinTokens{
		ByExpiresBefore: expiresBefore,
	})
	if err != nil {
		return err
	}

	var errCount int
	var firstErr error
	for _, record := range records {
		if err := ds.joinTokens.Delete(ctx, record.Object.JoinToken.Token); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			errCount++
		}
	}

	if firstErr != nil {
		return dsErr(firstErr, "failed pruning %d of %d entries: first error", errCount, len(records))
	}
	return nil
}

type joinTokenObject struct {
	JoinToken *datastore.JoinToken
}

func (o joinTokenObject) Key() string {
	if o.JoinToken == nil {
		return ""
	}
	return o.JoinToken.Token
}

type joinTokenCodec struct{}

func (joinTokenCodec) Marshal(o *joinTokenObject) (string, []byte, error) {
	data, err := json.Marshal(o.JoinToken)
	if err != nil {
		return "", nil, err
	}
	return o.Key(), data, nil
}

func (joinTokenCodec) Unmarshal(in []byte, out *joinTokenObject) error {
	joinToken := new(datastore.JoinToken)
	if err := json.Unmarshal(in, joinToken); err != nil {
		return err
	}
	out.JoinToken = joinToken
	return nil
}

type listJoinTokens struct {
	ByExpiresBefore time.Time
}

type joinTokenIndex struct {
	expiresAt record.UnaryIndex[int64]
}

func (c *joinTokenIndex) SetUp() {
	c.expiresAt.SetQuery("Object.JoinToken.Expiry")
}

func (c *joinTokenIndex) List(opts *listJoinTokens) (*keyvalue.ListObject, error) {
	list := new(keyvalue.ListObject)

	list.Cursor = ""
	list.Limit = -1

	if !opts.ByExpiresBefore.IsZero() {
		list.Filters = append(list.Filters, c.expiresAt.LessThan(opts.ByExpiresBefore.Unix()))
	}

	return list, nil
}
