package record

import (
	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/keyvalue"
	"time"
)

type Object interface {
	Key() string
}

type Metadata struct {
	CreatedAt time.Time
	UpdatedAt time.Time
	Revision  int64
}

type Record[O any] struct {
	Metadata Metadata
	Object   O
}

type Index[O Object, L any] interface {
	List(L) (*keyvalue.ListObject, error)
	Get(*Record[O])
	SetUp()
}

type Codec[O any] interface {
	Marshal(o *O) (string, []byte, error)
	Unmarshal(in []byte, out *O) error
}
