package testkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	keys          Keys
	rsa2048Bucket bucket[rsa2048, *rsa.PrivateKey]
	rsa4096Bucket bucket[rsa4096, *rsa.PrivateKey]
	ec256Bucket   bucket[ec256, *ecdsa.PrivateKey]
	ec384Bucket   bucket[ec384, *ecdsa.PrivateKey]
)

func NewRSA2048(tb testing.TB) *rsa.PrivateKey {
	return keys.NewRSA2048(tb)
}

func MustRSA2048() *rsa.PrivateKey {
	return keys.MustRSA2048()
}

func NewRSA4096(tb testing.TB) *rsa.PrivateKey {
	return keys.NewRSA4096(tb)
}

func MustRSA4096() *rsa.PrivateKey {
	return keys.MustRSA4096()
}

func NewEC256(tb testing.TB) *ecdsa.PrivateKey {
	return keys.NewEC256(tb)
}

func MustEC256() *ecdsa.PrivateKey {
	return keys.MustEC256()
}

func NewEC384(tb testing.TB) *ecdsa.PrivateKey {
	return keys.NewEC384(tb)
}

func MustEC384() *ecdsa.PrivateKey {
	return keys.MustEC384()
}

type Keys struct {
	mtx        sync.Mutex
	rsa2048Idx int
	rsa4096Idx int
	ec256Idx   int
	ec384Idx   int
}

func (ks *Keys) NewRSA2048(tb testing.TB) *rsa.PrivateKey {
	key, err := ks.NextRSA2048()
	require.NoError(tb, err)
	return key
}

func (ks *Keys) MustRSA2048() *rsa.PrivateKey {
	key, err := ks.NextRSA2048()
	check(err)
	return key
}

func (ks *Keys) NextRSA2048() (*rsa.PrivateKey, error) {
	ks.mtx.Lock()
	defer ks.mtx.Unlock()
	key, err := rsa2048Bucket.At(ks.rsa2048Idx)
	if err != nil {
		return nil, err
	}
	ks.rsa2048Idx++
	return key, nil
}

func (ks *Keys) NewRSA4096(tb testing.TB) *rsa.PrivateKey {
	key, err := ks.NextRSA4096()
	require.NoError(tb, err)
	return key
}

func (ks *Keys) MustRSA4096() *rsa.PrivateKey {
	key, err := ks.NextRSA4096()
	check(err)
	return key
}

func (ks *Keys) NextRSA4096() (*rsa.PrivateKey, error) {
	ks.mtx.Lock()
	defer ks.mtx.Unlock()
	key, err := rsa4096Bucket.At(ks.rsa4096Idx)
	if err != nil {
		return nil, err
	}
	ks.rsa4096Idx++
	return key, nil
}

func (ks *Keys) NewEC256(tb testing.TB) *ecdsa.PrivateKey {
	key, err := ks.NextEC256()
	require.NoError(tb, err)
	return key
}

func (ks *Keys) MustEC256() *ecdsa.PrivateKey {
	key, err := ks.NextEC256()
	check(err)
	return key
}

func (ks *Keys) NextEC256() (*ecdsa.PrivateKey, error) {
	ks.mtx.Lock()
	defer ks.mtx.Unlock()
	key, err := ec256Bucket.At(ks.ec256Idx)
	if err != nil {
		return nil, err
	}
	ks.ec256Idx++
	return key, nil
}

func (ks *Keys) NewEC384(tb testing.TB) *ecdsa.PrivateKey {
	key, err := ks.NextEC384()
	require.NoError(tb, err)
	return key
}

func (ks *Keys) MustEC384() *ecdsa.PrivateKey {
	key, err := ks.NextEC384()
	check(err)
	return key
}

func (ks *Keys) NextEC384() (*ecdsa.PrivateKey, error) {
	ks.mtx.Lock()
	defer ks.mtx.Unlock()
	key, err := ec384Bucket.At(ks.ec384Idx)
	if err != nil {
		return nil, err
	}
	ks.ec384Idx++
	return key, nil
}

type rsa2048 struct{}

func (rsa2048) Path() string { return "rsa2048.pem" }

func (rsa2048) GenerateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

type rsa4096 struct{}

func (rsa4096) Path() string { return "rsa4096.pem" }

func (rsa4096) GenerateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 4096)
}

type ec256 struct{}

func (ec256) Path() string { return "ec256.pem" }

func (ec256) GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

type ec384 struct{}

func (ec384) Path() string { return "ec384.pem" }

func (ec384) GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
