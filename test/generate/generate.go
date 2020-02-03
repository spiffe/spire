package generate

import (
	"encoding/hex"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
	"time"
)

var (
	// Random provides a random source for tests.
	Random = rand.New(rand.NewSource(time.Now().Unix()))
)

// MustGenerate generates and returns a random value of a type or fails a test.
func MustGenerate(tipe reflect.Type, test *testing.T) reflect.Value {
	value, ok := quick.Value(tipe, Random)
	if !ok {
		test.Errorf("unable to generate random value of type [%s]", tipe)
	}

	return value
}

// MustGenerateBytes generates a random slice of bytes or fails a test.
func MustGenerateBytes(test *testing.T) []byte {
	return MustGenerate(reflect.TypeOf([]byte{}), test).Interface().([]byte)
}

// MustGenerateHex generates a random hexadecimal string or fails a test.
func MustGenerateHex(test *testing.T) string {
	return hex.EncodeToString(MustGenerateBytes(test))
}
