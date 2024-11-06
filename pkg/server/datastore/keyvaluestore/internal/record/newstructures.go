package record

import (
	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/keyvalue"
)

type UnaryIndex[F any] struct {
	querry  string
	idxType F
}

func (idx *UnaryIndex[F]) SetQuerry(querry string) {
	idx.querry = querry
}

func (idx *UnaryIndex[F]) LessThan(pivot F) keyvalue.ListOp {
	return keyvalue.ListOp{
		Name:  idx.querry,
		Op:    keyvalue.LessThan,
		Value: pivot,
	}
}

func (idx *UnaryIndex[F]) GreaterThan(pivot F) keyvalue.ListOp {
	return keyvalue.ListOp{
		Name:  idx.querry,
		Op:    keyvalue.GreaterThan,
		Value: pivot,
	}
}

func (idx *UnaryIndex[F]) EqualTo(field F) keyvalue.ListOp {
	return keyvalue.ListOp{
		Name:  idx.querry,
		Op:    keyvalue.EqualTo,
		Value: field,
	}
}

type MultiIndex[F any] struct {
	querry  string
	idxType F
}

func (idx *MultiIndex[F]) SetQuerry(querry string) {
	idx.querry = querry
}

func (idx *MultiIndex[F]) Matching(fields []F, match keyvalue.MatchBehavior) keyvalue.ListOp {
	return keyvalue.ListOp{
		Name:  idx.querry,
		Op:    match,
		Value: fields,
	}
}
