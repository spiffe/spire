package record

import (
	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/keyvalue"
)

type UnaryIndex[F any] struct {
	query   string
	idxType F
}

func (idx *UnaryIndex[F]) SetQuery(query string) {
	idx.query = query
}

func (idx *UnaryIndex[F]) LessThan(pivot F) keyvalue.ListOp {
	return keyvalue.ListOp{
		Name:  idx.query,
		Op:    keyvalue.LessThan,
		Value: pivot,
	}
}

func (idx *UnaryIndex[F]) GreaterThan(pivot F) keyvalue.ListOp {
	return keyvalue.ListOp{
		Name:  idx.query,
		Op:    keyvalue.GreaterThan,
		Value: pivot,
	}
}

func (idx *UnaryIndex[F]) EqualTo(field F) keyvalue.ListOp {
	return keyvalue.ListOp{
		Name:  idx.query,
		Op:    keyvalue.EqualTo,
		Value: field,
	}
}

type MultiIndex[F any] struct {
	query   string
	idxType F
}

func (idx *MultiIndex[F]) SetQuery(query string) {
	idx.query = query
}

func (idx *MultiIndex[F]) Matching(fields []F, match keyvalue.MatchBehavior) keyvalue.ListOp {
	return keyvalue.ListOp{
		Name:  idx.query,
		Op:    match,
		Value: fields,
	}
}
