package keyvalue

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("record not found")
	ErrConflict = errors.New("record conflict")
	ErrExists   = errors.New("record already exists")
)

type MatchBehavior int

const (
	MatchAny MatchBehavior = iota + 1
	MatchExact
	MatchSuperset
	MatchSubset

	LessThan
	GreaterThan
	EqualTo
)

type ListObject struct {
	Cursor  string
	Limit   int
	Filters []ListOp
}

type ListOp struct {
	Name  string
	Op    MatchBehavior
	Value interface{}
}

type Metadata struct {
	CreatedAt time.Time
	UpdatedAt time.Time
	Revision  int64
}

type Record struct {
	Metadata
	Kind      string
	Key       string
	Object    interface{}
	ByteValue []byte
}

type Store interface {
	Get(ctx context.Context, kind, key string) (Record, error)
	Create(ctx context.Context, kind, key string, value interface{}, byteValue []byte) error
	Update(ctx context.Context, kind, key string, value interface{}, byteValue []byte, revision int64) error
	Replace(ctx context.Context, kind, key string, value interface{}, byteValue []byte) error
	Delete(ctx context.Context, kind, key string) error
	Batch(ctx context.Context, ops []Op) error
	AtomicCounter(ctx context.Context, kind string) (uint, error)
	List(ctx context.Context, kind string, filters *ListObject) ([]Record, string, error)
	Close() error
}

type Op struct {
	Kind     string
	Key      string
	Value    interface{}
	Revision int64
	Type     OpType
}

type OpType int

const (
	CreateOp OpType = iota
	UpdateOp
	ReplaceOp
	DeleteOp
)

type Key struct {
	Kind string
	Key  string
}
