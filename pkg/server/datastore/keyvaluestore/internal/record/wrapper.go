package record

import (
	"context"

	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/keyvalue"
)

var (
	ErrNotFound = keyvalue.ErrNotFound
	ErrConflict = keyvalue.ErrConflict
	ErrExists   = keyvalue.ErrExists
)

func NewWrapper[C Codec[O], I Index[O, L], O Object, L any](store keyvalue.Store, kind string, index I) *Wrapper[C, I, O, L] {
	index.SetUp()
	return &Wrapper[C, I, O, L]{store: store, kind: kind, index: index}
}

type Wrapper[C Codec[O], I Index[O, L], O Object, L any] struct {
	kind  string
	codec C

	store keyvalue.Store
	index I
}

func (c *Wrapper[C, I, O, L]) Kind() string {
	return c.kind
}

func (c *Wrapper[C, I, O, L]) Get(ctx context.Context, key string) (*Record[O], error) {
	kv, err := c.store.Get(ctx, c.kind, key)
	if err != nil {
		return nil, err
	}

	r := &Record[O]{
		Metadata: Metadata(kv.Metadata),
	}

	if err := c.codec.Unmarshal(kv.ByteValue, &r.Object); err != nil {
		return nil, err
	}

	c.index.Get(r)
	return r, nil
}

func (c *Wrapper[C, I, O, L]) Create(ctx context.Context, o O) error {
	key, byteValue, err := c.codec.Marshal(&o)
	if err != nil {
		return err
	}

	if err := c.store.Create(ctx, c.kind, key, o, byteValue); err != nil {
		return err
	}
	return nil
}

func (c *Wrapper[C, I, O, L]) Update(ctx context.Context, o O, revision int64) error {
	key, byteValue, err := c.codec.Marshal(&o)
	if err != nil {
		return err
	}

	if err := c.store.Update(ctx, c.kind, key, o, byteValue, revision); err != nil {
		return err
	}
	return nil
}

func (c *Wrapper[C, I, O, L]) Replace(ctx context.Context, o O) error {
	key, byteValue, err := c.codec.Marshal(&o)
	if err != nil {
		return err
	}

	if err := c.store.Replace(ctx, c.kind, key, o, byteValue); err != nil {
		return err
	}

	return nil
}

func (c *Wrapper[C, I, O, L]) Delete(ctx context.Context, key string) error {
	if err := c.store.Delete(ctx, c.kind, key); err != nil {
		return err
	}
	return nil
}

func (c *Wrapper[C, I, O, L]) List(ctx context.Context, opts L) ([]*Record[O], string, error) {
	filters, err := c.index.List(opts)
	if err != nil {
		return nil, "", err
	}

	kvRecords, nextCursor, err := c.store.List(ctx, c.kind, filters)

	if err != nil {
		return nil, "", err
	}

	var rs []*Record[O]
	for _, kv := range kvRecords {
		r := &Record[O]{
			Metadata: Metadata(kv.Metadata),
		}

		if err := c.codec.Unmarshal(kv.ByteValue, &r.Object); err != nil {
			return nil, "", err
		}
		c.index.Get(r)
		rs = append(rs, r)
	}

	return rs, nextCursor, nil
}
