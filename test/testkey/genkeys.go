// +build ignore

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"go/format"
	"io"
	"os"

	"github.com/spiffe/spire/test/testkey"
)

const (
	header = ` // THIS FILE IS GENERATED. DO NOT EDIT THIS FILE DIRECTLY UNLESS YOU ARE
// SEEDING A NEW KEY TYPE.
//
// To seed a new key type, add an empty exported []string variable for that
// key type and adjust the code in generate.sh and genkeys.go accordingly.
package testkey

var (
`
	footer = `)
`
)

func main() {
	rsa2048 := flag.Int("rsa2048", 0, "Number of rsa2048 keys to generate")
	rsa4096 := flag.Int("rsa4096", 0, "Number of rsa4096 keys to generate")
	ec256 := flag.Int("ec256", 0, "Number of ec256 keys to generate")
	ec384 := flag.Int("ec384", 0, "Number of ec384 keys to generate")
	flag.Parse()

	buf := new(bytes.Buffer)

	fmt.Fprintln(buf, header)

	writeKeys(buf, "RSA2048Keys", testkey.RSA2048Keys, *rsa2048, genRSA2048)
	writeKeys(buf, "RSA4096Keys", testkey.RSA4096Keys, *rsa4096, genRSA4096)
	writeKeys(buf, "EC256Keys", testkey.EC256Keys, *ec256, genEC256)
	writeKeys(buf, "EC384Keys", testkey.EC384Keys, *ec384, genEC384)

	fmt.Fprintln(buf, footer)

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		os.Stderr.Write(buf.Bytes())
		panic(err)
	}
	_, err = os.Stdout.Write(formatted)
	check(err)
}

func writeKeys(buf io.Writer, varName string, existing []string, wanted int, genKey func() crypto.PrivateKey) {
	fmt.Fprintf(buf, "%s = []string{\n", varName)
	for i := 0; i < wanted; i++ {
		if i < len(existing) {
			fmt.Fprintf(buf, "`%s`,\n", existing[i])
		} else {
			fmt.Fprintf(buf, "`%s`,\n", toPEM(genKey()))
		}
	}
	fmt.Fprintln(buf, "}")
}

func genRSA2048() crypto.PrivateKey { return genRSA(2048) }
func genRSA4096() crypto.PrivateKey { return genRSA(4096) }
func genEC256() crypto.PrivateKey   { return genEC(elliptic.P256()) }
func genEC384() crypto.PrivateKey   { return genEC(elliptic.P384()) }

func genRSA(bits int) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	check(err)
	return key
}

func genEC(curve elliptic.Curve) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	check(err)
	return key
}

func toPEM(key crypto.PrivateKey) string {
	data, err := x509.MarshalPKCS8PrivateKey(key)
	check(err)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: data,
	}))
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
