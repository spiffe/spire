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

var (
	keysMtx sync.Mutex

	rsa1024Idx int
	rsa2048Idx int
	rsa4096Idx int
	ec256Idx   int
	ec384Idx   int
)

func NewRSA1024(t *testing.T) *rsa.PrivateKey {
	keysMtx.Lock()
	defer keysMtx.Unlock()
	if rsa1024Idx >= len(rsa1024Keys) {
		t.Fatalf("exhausted %d pregenerated RSA 1024 test keys in test; use generate.sh to increase amount or refactor test to use less keys", len(rsa1024Keys))
	}
	key, err := pemutil.ParseRSAPrivateKey([]byte(rsa1024Keys[rsa1024Idx]))
	require.NoError(t, err)
	rsa1024Idx++
	return key
}

func NewRSA2048(t *testing.T) *rsa.PrivateKey {
	keysMtx.Lock()
	defer keysMtx.Unlock()
	if rsa2048Idx >= len(rsa2048Keys) {
		t.Fatalf("exhausted %d pregenerated RSA 2048 test keys in test; use generate.sh to increase amount or refactor test to use less keys", len(rsa2048Keys))
	}
	key, err := pemutil.ParseRSAPrivateKey([]byte(rsa2048Keys[rsa2048Idx]))
	require.NoError(t, err)
	rsa2048Idx++
	return key
}

func NewRSA4096(t *testing.T) *rsa.PrivateKey {
	keysMtx.Lock()
	defer keysMtx.Unlock()
	if rsa4096Idx >= len(rsa4096Keys) {
		t.Fatalf("exhausted %d pregenerated RSA 2048 test keys in test; use generate.sh to increase amount or refactor test to use less keys", len(rsa4096Keys))
	}
	key, err := pemutil.ParseRSAPrivateKey([]byte(rsa4096Keys[rsa4096Idx]))
	require.NoError(t, err)
	rsa4096Idx++
	return key
}

func NewEC256(t *testing.T) *ecdsa.PrivateKey {
	key, err := newEC256()
	require.NoError(t, err)
	return key
}

func MustEC256() *ecdsa.PrivateKey {
	key, err := newEC256()
	check(err)
	return key
}

func newEC256() (*ecdsa.PrivateKey, error) {
	keysMtx.Lock()
	defer keysMtx.Unlock()
	if ec256Idx >= len(ec256Keys) {
		return nil, fmt.Errorf("exhausted %d pregenerated RSA 2048 test keys in test; use generate.sh to increase amount or refactor test to use less keys", len(ec256Keys))
	}
	key, err := pemutil.ParseECPrivateKey([]byte(ec256Keys[ec256Idx]))
	if err != nil {
		return nil, err
	}
	ec256Idx++
	return key, nil
}

func NewEC384(t *testing.T) *ecdsa.PrivateKey {
	keysMtx.Lock()
	defer keysMtx.Unlock()
	if ec384Idx >= len(ec384Keys) {
		t.Fatalf("exhausted %d pregenerated RSA 2048 test keys in test; use generate.sh to increase amount or refactor test to use less keys", len(ec384Keys))
	}
	key, err := pemutil.ParseECPrivateKey([]byte(ec384Keys[ec384Idx]))
	require.NoError(t, err)
	ec384Idx++
	return key
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
