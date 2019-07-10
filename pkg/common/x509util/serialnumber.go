package x509util

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
)

// NewSerialNumber creates a random certificate serial number according to CA/Browser forum spec
// Section 7.1:
//   "Effective September 30, 2016, CAs SHALL generate non-sequential Certificate serial numbers greater than
//   zero (0) containing at least 64 bits of output from a CSPRNG"
func NewSerialNumber() (*big.Int, error) {
	// Get MaxUint64 as big.Int
	maxUInt64 := new(big.Int)
	maxUInt64 = maxUInt64.SetUint64(math.MaxUint64)

	// Creates random integer in range [0,MaxUint64)
	s, err := rand.Int(rand.Reader, maxUInt64)
	if err != nil {
		return nil, fmt.Errorf("cannot create random number: %v", err)
	}

	// Adds 1 to return serial number [1,MaxUint64]
	s.Add(s, big.NewInt(1))
	return s, nil
}
