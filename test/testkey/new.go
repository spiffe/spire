package testkey

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"sync"
	"testing"

	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/stretchr/testify/require"
)

var keys Keys

func NewRSA1024(tb testing.TB) *rsa.PrivateKey {
	return keys.NewRSA1024(tb)
}

func MustRSA1024() *rsa.PrivateKey {
	return keys.MustRSA1024()
}

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
	mtx sync.Mutex

	rsa1024Idx int
	rsa2048Idx int
	rsa4096Idx int
	ec256Idx   int
	ec384Idx   int
}

func (ks *Keys) NewRSA1024(tb testing.TB) *rsa.PrivateKey {
	key, err := ks.newRSA1024()
	require.NoError(tb, err)
	return key
}

func (ks *Keys) MustRSA1024() *rsa.PrivateKey {
	key, err := ks.newRSA1024()
	check(err)
	return key
}

func (ks *Keys) newRSA1024() (*rsa.PrivateKey, error) {
	ks.mtx.Lock()
	defer ks.mtx.Unlock()
	if ks.rsa1024Idx >= len(RSA1024Keys) {
		return nil, fmt.Errorf("exhausted %d pregenerated RSA-1024 test keys in test; use generate.sh to increase amount or refactor test to use less keys", len(RSA1024Keys))
	}
	key, err := pemutil.ParseRSAPrivateKey([]byte(RSA1024Keys[ks.rsa1024Idx]))
	if err != nil {
		return nil, err
	}
	ks.rsa1024Idx++
	return key, nil
}

func (ks *Keys) NewRSA2048(tb testing.TB) *rsa.PrivateKey {
	key, err := ks.newRSA2048()
	require.NoError(tb, err)
	return key
}

func (ks *Keys) MustRSA2048() *rsa.PrivateKey {
	key, err := ks.newRSA2048()
	check(err)
	return key
}

func (ks *Keys) newRSA2048() (*rsa.PrivateKey, error) {
	ks.mtx.Lock()
	defer ks.mtx.Unlock()
	if ks.rsa2048Idx >= len(RSA2048Keys) {
		return nil, fmt.Errorf("exhausted %d pregenerated RSA-2048 test keys in test; use generate.sh to increase amount or refactor test to use less keys", len(RSA2048Keys))
	}
	key, err := pemutil.ParseRSAPrivateKey([]byte(RSA2048Keys[ks.rsa2048Idx]))
	if err != nil {
		return nil, err
	}
	ks.rsa2048Idx++
	return key, nil
}

func (ks *Keys) NewRSA4096(tb testing.TB) *rsa.PrivateKey {
	key, err := ks.newRSA4096()
	require.NoError(tb, err)
	return key
}

func (ks *Keys) MustRSA4096() *rsa.PrivateKey {
	key, err := ks.newRSA4096()
	check(err)
	return key
}

func (ks *Keys) newRSA4096() (*rsa.PrivateKey, error) {
	ks.mtx.Lock()
	defer ks.mtx.Unlock()
	if ks.rsa4096Idx >= len(RSA4096Keys) {
		return nil, fmt.Errorf("exhausted %d pregenerated RSA-4096 test keys in test; use generate.sh to increase amount or refactor test to use less keys", len(RSA4096Keys))
	}
	key, err := pemutil.ParseRSAPrivateKey([]byte(RSA4096Keys[ks.rsa4096Idx]))
	if err != nil {
		return nil, err
	}
	ks.rsa4096Idx++
	return key, nil
}

func (ks *Keys) NewEC256(tb testing.TB) *ecdsa.PrivateKey {
	key, err := ks.newEC256()
	require.NoError(tb, err)
	return key
}

func (ks *Keys) MustEC256() *ecdsa.PrivateKey {
	key, err := ks.newEC256()
	check(err)
	return key
}

func (ks *Keys) newEC256() (*ecdsa.PrivateKey, error) {
	ks.mtx.Lock()
	defer ks.mtx.Unlock()
	if ks.ec256Idx >= len(EC256Keys) {
		return nil, fmt.Errorf("exhausted %d pregenerated EC-256 test keys in test; use generate.sh to increase amount or refactor test to use less keys", len(EC256Keys))
	}
	key, err := pemutil.ParseECPrivateKey([]byte(EC256Keys[ks.ec256Idx]))
	if err != nil {
		return nil, err
	}
	ks.ec256Idx++
	return key, nil
}

func (ks *Keys) NewEC384(tb testing.TB) *ecdsa.PrivateKey {
	key, err := ks.newEC384()
	require.NoError(tb, err)
	return key
}

func (ks *Keys) MustEC384() *ecdsa.PrivateKey {
	key, err := ks.newEC384()
	check(err)
	return key
}

func (ks *Keys) newEC384() (*ecdsa.PrivateKey, error) {
	ks.mtx.Lock()
	defer ks.mtx.Unlock()
	if ks.ec384Idx >= len(EC384Keys) {
		return nil, fmt.Errorf("exhausted %d pregenerated EC-384 test keys in test; use generate.sh to increase amount or refactor test to use less keys", len(EC384Keys))
	}
	key, err := pemutil.ParseECPrivateKey([]byte(EC384Keys[ks.ec384Idx]))
	if err != nil {
		return nil, err
	}
	ks.ec384Idx++
	return key, nil
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
