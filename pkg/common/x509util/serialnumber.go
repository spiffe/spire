package x509util

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

var (
	maxUint128, ok = new(big.Int).SetString("340282366920938463463374607431768211455", 10) //(2^128 − 1)
	one            = big.NewInt(1)
)

// NewSerialNumber creates a random certificate serial number according to CA/Browser forum spec
// Section 7.1:
//   "Effective September 30, 2016, CAs SHALL generate non-sequential Certificate serial numbers greater than
//   zero (0) containing at least 64 bits of output from a CSPRNG"
func NewSerialNumber() (*big.Int, error) {
	if !ok {
		return nil, fmt.Errorf("cannot parse value for max unsigned int 128")
	}

	// Creates random integer in range [0,MaxUint128)
	s, err := rand.Int(rand.Reader, maxUint128)
	if err != nil {
		return nil, fmt.Errorf("cannot create random number: %v", err)
	}

	// Adds 1 to return serial number [1,MaxUint128]
	return s.Add(s, one), nil
}
