package protokv

import (
	"context"

	"github.com/zeebo/errs"
)

var NotFound = errs.Class("not found")

type SetOp int

const (
	SetIntersect SetOp = iota
	SetUnion

	SetDefault = SetIntersect
)

type Index struct {
	Prefixes [][]byte
	SetOp    SetOp
}

type KVOps interface {
	Get(ctx context.Context, key []byte) ([]byte, error)
	Put(ctx context.Context, key, value []byte) error
	Delete(ctx context.Context, key []byte) (bool, error)
	Page(ctx context.Context, prefix []byte, token []byte, limit int) ([][]byte, []byte, error)
	PageIndex(ctx context.Context, indices []Index, token []byte, limit int) ([][]byte, []byte, error)
}

type KV interface {
	KVOps

	Begin(ctx context.Context) (Tx, error)
	Close() error
}

type Tx interface {
	KVOps

	Commit() error
	Rollback() error
}
