package util

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

type (
	int8Wrapper  int8
	int16Wrapper int16
	int32Wrapper int32
	uint8Wrapper uint8
)

func TestCheckedCast(t *testing.T) {
	assertCastOK[uint8](t, int8(3))
	assertCastOK[int16](t, int8(3))
	assertCastFail[uint8](t, int8(-3))
	assertCastOK[int16](t, int8(-3))
	assertCastOK[uint8](t, int16(200))
	assertCastOK[uint16](t, int16(200))
	assertCastFail[uint8](t, int16(300))
	assertCastOK[int16](t, int16(300))
	assertCastOK[uint8](t, uint64(1))
	assertCastOK[int16](t, uint64(1))

	assertCastOK[int16](t, int32(0))
	assertCastOK[int16](t, int32(-1))
	assertCastFail[int16](t, int32(1_000_000))

	assertCastFail[int8](t, uint64(math.MaxUint64))
	assertCastFail[int16](t, uint64(math.MaxUint64))
	assertCastFail[int32](t, uint64(math.MaxUint64))
	assertCastFail[int64](t, uint64(math.MaxUint64))
	assertCastFail[uint8](t, uint64(math.MaxInt64))
	assertCastFail[uint16](t, uint64(math.MaxInt64))
	assertCastFail[uint32](t, uint64(math.MaxInt64))
	assertCastOK[uint64](t, uint64(math.MaxInt64))

	assertCastOK[int32](t, int16Wrapper(3))
	assertCastOK[uint8](t, int8Wrapper(3))
	assertCastFail[uint8](t, int8Wrapper(-3))

	assertCastOK[int32Wrapper](t, int16(3))
	assertCastOK[uint8Wrapper](t, int8Wrapper(3))
	assertCastFail[uint8Wrapper](t, int8Wrapper(-3))

	assertCastOK[int32Wrapper](t, int16Wrapper(3))
	assertCastOK[uint8Wrapper](t, int8(3))
	assertCastFail[uint8Wrapper](t, int8(-3))
}

func assertCastOK[To, From Int](t *testing.T, v From) {
	t.Helper()
	assert := assert.New(t)

	x, err := CheckedCast[To](v)
	assert.Equal(To(v), x)
	assert.NoError(err)

	var y To
	assert.NotPanics(func() { y = MustCast[To](v) })
	assert.Equal(To(v), y)
}

func assertCastFail[To, From Int](t *testing.T, v From) {
	t.Helper()
	assert := assert.New(t)

	x, err := CheckedCast[To](v)
	assert.ErrorContains(err, "overflow")
	assert.Equal(To(0), x)

	assert.Panics(func() { MustCast[To](v) })
}
