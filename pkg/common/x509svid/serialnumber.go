package x509svid

import (
	"context"
	"math/big"
	"sync/atomic"
)

type SerialNumber interface {
	NextNumber(context.Context) (*big.Int, error)
}

type serialNumber struct {
	next int64
}

func NewSerialNumber() SerialNumber {
	return &serialNumber{}
}

func (m *serialNumber) NextNumber(ctx context.Context) (*big.Int, error) {
	return big.NewInt(atomic.AddInt64(&m.next, 1)), nil
}
