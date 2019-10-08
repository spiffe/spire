package main

import (
	"crypto/x509"

	"github.com/spiffe/spire/pkg/common/pemutil"
)

var (
	ec256Pubkey, _ = pemutil.ParsePublicKey([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiSt7S4ih6QLodw9wf+zdPV8bmAlD
JBCRRy24/UAZY70ZviCRAJ4ePscJtnN1y1wDH13GgOAL2y52xIbtkshYmw==
-----END PUBLIC KEY-----`))
	ec256PubkeyPKIX, _ = x509.MarshalPKIXPublicKey(ec256Pubkey)
)
