package protokv

import (
	"context"

	"github.com/zeebo/errs"
)

type Store struct {
	kv  KV
	msg *Message
}

func NewStore(kv KV, msg *Message) *Store {
	return &Store{
		kv:  kv,
		msg: msg,
	}
}

func (s *Store) Create(ctx context.Context, value []byte) error {
	return Create(ctx, s.kv, s.msg, value)
}

func (s *Store) Upsert(ctx context.Context, value []byte) error {
	return Create(ctx, s.kv, s.msg, value)
}

func (s *Store) Update(ctx context.Context, value []byte) error {
	return Update(ctx, s.kv, s.msg, value)
}

func (s *Store) Read(ctx context.Context, value []byte) ([]byte, error) {
	return Read(ctx, s.kv, s.msg, value)
}

func (s *Store) Page(ctx context.Context, token []byte, limit int) ([][]byte, []byte, error) {
	return Page(ctx, s.kv, s.msg, token, limit)
}

func (s *Store) PageIndex(ctx context.Context, value, token []byte, limit int, fields []Field, setOps []SetOp) ([][]byte, []byte, error) {
	return PageIndex(ctx, s.kv, s.msg, value, token, limit, fields, setOps)
}

func (s *Store) Delete(ctx context.Context, value []byte) (bool, error) {
	return Delete(ctx, s.kv, s.msg, value)
}

func Create(ctx context.Context, kv KV, msg *Message, value []byte) error {
	keys, err := getFieldKeys(value, append([]Field{msg.PrimaryKey}, msg.Indices...)...)
	if err != nil {
		return err
	}

	pk, err := EncodeKeys(msg.ID, msg.PrimaryKey, keys[0])
	if err != nil {
		return errs.New("primary key field is not set")
	}
	if len(pk) > 1 {
		return errs.New("primary key field cannot be repeated")
	}
	indices := keys[1:]

	// Build up a list of keys to insert so we can hold the tx for as small
	// a time as possible.
	kvKeys := [][]byte{
		pk[0],
	}
	for i, index := range indices {
		indexKeys, err := EncodeIndexKeys(msg.ID, msg.Indices[i], index, pk[0])
		if err != nil {
			return err
		}
		kvKeys = append(kvKeys, indexKeys...)
	}

	return withTx(ctx, kv, func(tx Tx) error {
		for i, kvKey := range kvKeys {
			var kvValue []byte
			if i == 0 {
				// first key is the primary key...
				kvValue = value
			}
			if err := tx.Put(ctx, kvKey, kvValue); err != nil {
				return err
			}
		}
		return nil
	})
}

func Update(ctx context.Context, kv KV, msg *Message, newValue []byte) error {
	fields := append([]Field{msg.PrimaryKey}, msg.Indices...)
	keys, err := getFieldKeys(newValue, fields...)
	if err != nil {
		return err
	}

	pk, err := EncodeKeys(msg.ID, msg.PrimaryKey, keys[0])
	if err != nil {
		return errs.New("primary key field is not set")
	}
	if len(pk) > 1 {
		return errs.New("primary key field cannot be repeated")
	}
	indices := keys[1:]

	// Build up a list of keys to insert so we can hold the tx for as small
	// a time as possible.
	newKeys := [][]byte{pk[0]}
	for i, index := range indices {
		indexKeys, err := EncodeIndexKeys(msg.ID, msg.Indices[i], index, pk[0])
		if err != nil {
			return err
		}
		newKeys = append(newKeys, indexKeys...)
	}

	return withTx(ctx, kv, func(tx Tx) error {
		// Get the message stored under the primary key
		oldValue, err := tx.Get(ctx, pk[0])
		if err != nil {
			return errs.Wrap(err)
		}

		// TODO: be smarter about which keys to delete/add (i.e. detect for
		// keys present in both old and new.

		// Gather keys to delete
		oldKeys, err := getExistingKeys(msg.ID, tx, oldValue, fields)
		if err != nil {
			return err
		}

		// Delete those no longer applying to the message.
		for _, oldKey := range oldKeys {
			if _, err := tx.Delete(ctx, oldKey); err != nil {
				return err
			}
		}

		// Set those new to the message.
		for i, newKey := range newKeys {
			var kvValue []byte
			if i == 0 {
				// first key is the primary key...
				kvValue = newValue
			}
			if err := tx.Put(ctx, newKey, kvValue); err != nil {
				return err
			}
		}

		return nil
	})
}

func Upsert(ctx context.Context, kv KV, msg *Message, newValue []byte) error {
	fields := append([]Field{msg.PrimaryKey}, msg.Indices...)
	keys, err := getFieldKeys(newValue, fields...)
	if err != nil {
		return err
	}

	pk, err := EncodeKeys(msg.ID, msg.PrimaryKey, keys[0])
	if err != nil {
		return errs.New("primary key field is not set")
	}
	if len(pk) > 1 {
		return errs.New("primary key field cannot be repeated")
	}
	indices := keys[1:]

	// Build up a list of keys to insert so we can hold the tx for as small
	// a time as possible.
	newKeys := [][]byte{pk[0]}
	for i, index := range indices {
		indexKeys, err := EncodeIndexKeys(msg.ID, msg.Indices[i], index, pk[0])
		if err != nil {
			return err
		}
		newKeys = append(newKeys, indexKeys...)
	}

	return withTx(ctx, kv, func(tx Tx) error {
		// Get the message stored under the primary key
		oldValue, err := tx.Get(ctx, pk[0])
		if err != nil && !NotFound.Has(err) {
			return errs.Wrap(err)
		}

		// Gather keys to delete
		if oldValue != nil {
			// TODO: be smarter about which keys to delete/add (i.e. detect for
			// keys present in both old and new.

			oldKeys, err := getExistingKeys(msg.ID, tx, oldValue, fields)
			if err != nil {
				return err
			}

			// Delete those no longer applying to the message.
			for _, oldKey := range oldKeys {
				if _, err := tx.Delete(ctx, oldKey); err != nil {
					return err
				}
			}
		}

		// Set those new to the message.
		for i, newKey := range newKeys {
			var kvValue []byte
			if i == 0 {
				// first key is the primary key...
				kvValue = newValue
			}
			if err := tx.Put(ctx, newKey, kvValue); err != nil {
				return err
			}
		}

		return nil
	})
}

func Read(ctx context.Context, kv KV, msg *Message, value []byte) ([]byte, error) {
	keys, err := getFieldKeys(value, msg.PrimaryKey)
	if err != nil {
		return nil, err
	}

	pk, err := EncodeKeys(msg.ID, msg.PrimaryKey, keys[0])
	if err != nil {
		return nil, errs.New("primary key field is not set")
	}
	if len(pk) > 1 {
		return nil, errs.New("primary key field cannot be repeated")
	}

	return kv.Get(ctx, pk[0])
}

func Page(ctx context.Context, kv KV, msg *Message, token []byte, limit int) ([][]byte, []byte, error) {
	prefix := EncodeFieldPrefix(msg.ID, msg.PrimaryKey)
	return kv.Page(ctx, prefix, token, limit)
}

func PageIndex(ctx context.Context, kv KV, msg *Message, value, token []byte, limit int, fields []Field, setOps []SetOp) ([][]byte, []byte, error) {
	keys, err := getFieldKeys(value, fields...)
	if err != nil {
		return nil, nil, err
	}

	var indices []Index
	for i := range keys {
		prefixes, err := EncodeIndexKeys(msg.ID, fields[i], keys[i], nil)
		if err != nil {
			return nil, nil, err
		}
		setOp := SetUnion
		if len(setOps) > i {
			setOp = setOps[i]
		}
		indices = append(indices, Index{
			Prefixes: prefixes,
			SetOp:    setOp,
		})
	}

	return kv.PageIndex(ctx, indices, token, limit)
}

func Delete(ctx context.Context, kv KV, msg *Message, value []byte) (bool, error) {
	keys, err := getFieldKeys(value, msg.PrimaryKey)
	if err != nil {
		return false, err
	}

	pk, err := EncodeKeys(msg.ID, msg.PrimaryKey, keys[0])
	if err != nil {
		return false, errs.New("primary key field is not set")
	}
	if len(pk) > 1 {
		return false, errs.New("primary key field cannot be repeated")
	}

	fields := append([]Field{msg.PrimaryKey}, msg.Indices...)

	var found bool
	err = withTx(ctx, kv, func(tx Tx) error {
		oldValue, err := tx.Get(ctx, pk[0])
		if err != nil {
			if NotFound.Has(err) {
				return nil
			}
			return errs.Wrap(err)
		}

		// Gather keys to delete
		keys, err := getExistingKeys(msg.ID, tx, oldValue, fields)
		if err != nil {
			return err
		}
		for _, key := range keys {
			if _, err := tx.Delete(ctx, key); err != nil {
				return err
			}
		}
		return nil
	})
	return found, err
}

func withTx(ctx context.Context, kv KV, fn func(Tx) error) (err error) {
	tx, err := kv.Begin(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			err = errs.Combine(err, tx.Rollback())
		} else {
			err = tx.Commit()
		}
	}()

	return fn(tx)
}

func getExistingKeys(msgID uint64, tx Tx, value []byte, fields []Field) ([][]byte, error) {
	fieldKeys, err := getFieldKeys(value, fields...)
	if err != nil {
		return nil, err
	}

	// One key per field is a nice place to start the slice allocation at.
	// We could need more.
	// TODO: reduce allocations
	out := make([][]byte, 0, len(fieldKeys))

	for i, fieldKey := range fieldKeys {
		kvKeys, err := EncodeKeys(msgID, fields[i], fieldKey)
		if err != nil {
			return nil, err
		}
		out = append(out, kvKeys...)
	}
	return out, nil
}
