package record

import (
	"context"
	"sync"
	//"fmt"

	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/keyvalue"
)

var (
	ErrNotFound = keyvalue.ErrNotFound
	ErrConflict = keyvalue.ErrConflict
	ErrExists   = keyvalue.ErrExists
)

func NewCache[C Codec[O], I Index[O, L], O Object, L any](store keyvalue.Store, kind string, index I) *Cache[C, I, O, L] {
	index.SetUp()
	return &Cache[C, I, O, L]{store: store, kind: kind, index: index}
}

type Cache[C Codec[O], I Index[O, L], O Object, L any] struct {
	kind  string
	codec C

	mtx   sync.RWMutex
	store keyvalue.Store
	index I
}

func (c *Cache[C, I, O, L]) Kind() string {
	return c.kind
}

func (c *Cache[C, I, O, L]) Count() int {
	//return len(c.List)
	// TO-DO
	return 1
}

func (c *Cache[C, I, O, L]) ReadIndex(f func(i I)) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	f(c.index)
}

func (c *Cache[C, I, O, L]) Get(ctx context.Context, key string) (*Record[O], error) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	/* r, ok := c.index.Get(key)
	if !ok {
		return nil, ErrNotFound
	} */
	return c.get(ctx, key)
}

func (c *Cache[C, I, O, L]) List(ctx context.Context, opts L) ([]*Record[O], string, error) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

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

		rs = append(rs, r)
	}

	return rs, nextCursor, nil
}

func (c *Cache[C, I, O, L]) Create(ctx context.Context, o O) error {
	key, byteValue, err := c.codec.Marshal(&o)
	if err != nil {
		return err
	}

	if err := c.store.Create(ctx, c.kind, key, o, byteValue); err != nil {
		return err
	}
	return nil
}

func (c *Cache[C, I, O, L]) Update(ctx context.Context, o O, revision int64) error {
	key, byteValue, err := c.codec.Marshal(&o)
	if err != nil {
		return err
	}

	if err := c.store.Update(ctx, c.kind, key, o, byteValue, revision); err != nil {
		return err
	}
	return nil
}

func (c *Cache[C, I, O, L]) Replace(ctx context.Context, o O) error {
	key, byteValue, err := c.codec.Marshal(&o)
	if err != nil {
		return err
	}

	if err := c.store.Replace(ctx, c.kind, key, o, byteValue); err != nil {
		return err
	}

	return nil
}

func (c *Cache[C, I, O, L]) Delete(ctx context.Context, key string) error {
	if err := c.store.Delete(ctx, c.kind, key); err != nil {
		return err
	}
	return nil
}

func (c *Cache[C, I, O, L]) get(ctx context.Context, key string) (*Record[O], error) {
	kv, err := c.store.Get(ctx, c.kind, key)
	if err != nil {
		return nil, err
	}
	//fmt.Printf("%+v\n", kv.Value)

	r := &Record[O]{
		Metadata: Metadata(kv.Metadata),
	}

	if err := c.codec.Unmarshal(kv.ByteValue, &r.Object); err != nil {
		return nil, err
	}
	return r, nil
}
