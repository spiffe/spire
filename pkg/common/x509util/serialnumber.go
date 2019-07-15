package x509util

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
)

var (
	maxUint64 = new(big.Int).SetUint64(math.MaxUint64)
	one       = big.NewInt(1)
)

// NewSerialNumber creates a random certificate serial number according to CA/Browser forum spec
// Section 7.1:
//   "Effective September 30, 2016, CAs SHALL generate non-sequential Certificate serial numbers greater than
//   zero (0) containing at least 64 bits of output from a CSPRNG"
func NewSerialNumber() (*big.Int, error) {
	// Creates random integer in range [0,MaxUint64)
	s, err := rand.Int(rand.Reader, maxUint64)
	if err != nil {
		return nil, fmt.Errorf("cannot create random number: %v", err)
	}

	// Adds 1 to return serial number [1,MaxUint64]
	return s.Add(s, one), nil
}
