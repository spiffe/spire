package x509util

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSerialNumber(t *testing.T) {
	number1, err := NewSerialNumber()
	assert.NoError(t, err)
	assert.NotEqual(t, big.NewInt(0), number1, "Serial numbers must not be zero")

	number2, err := NewSerialNumber()
	assert.NotEqual(t, number1, number2, "Successive serial numbers must be different")
	assert.NotEqual(t, number1, number2.Add(number2, big.NewInt(-1)), "Serial numbers must not be sequential")
}

func TestMaxUint128IsMaxValueRepresentableWith128bits(t *testing.T) {
	assert.Equal(t, 128, maxUint128.BitLen())
	assert.Equal(t, 129, maxUint128.Add(maxUint128, one).BitLen())
}
