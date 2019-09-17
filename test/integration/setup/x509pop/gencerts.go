package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

var (
	// The "never expires" timestamp from RFC5280. Probably not a good
	// idea in practice.
	neverExpires = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: gencerts SERVERDIR AGENTDIR [AGENTDIR...]")
		os.Exit(1)
	}

	caKey := generateKey()
	caCert := createRootCertificate(caKey, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotAfter:              neverExpires,
		Subject:               pkix.Name{CommonName: "Agent CA"},
	})

	writeCerts(filepath.Join(os.Args[1], "agent-cacert.pem"), caCert)

	for i, dir := range os.Args[2:] {
		agentKey := generateKey()
		agentCert := createCertificate(agentKey, &x509.Certificate{
			SerialNumber: big.NewInt(int64(i)),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			NotAfter:     neverExpires,
			Subject:      pkix.Name{CommonName: filepath.Base(dir)},
		}, caKey, caCert)

		writeKey(filepath.Join(dir, "agent.key.pem"), agentKey)
		writeCerts(filepath.Join(dir, "agent.crt.pem"), agentCert)
	}
}

func createRootCertificate(key crypto.Signer, tmpl *x509.Certificate) *x509.Certificate {
	return createCertificate(key, tmpl, key, tmpl)
}

func createCertificate(key crypto.Signer, tmpl *x509.Certificate, parentKey crypto.Signer, parent *x509.Certificate) *x509.Certificate {
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	checkErr(err)
	cert, err := x509.ParseCertificate(certDER)
	checkErr(err)
	return cert
}

func generateKey() crypto.Signer {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	checkErr(err)
	return key
}

func writeKey(path string, key crypto.Signer) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	checkErr(err)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})
	writeFile(path, pemBytes, 0600)
}

func writeCerts(path string, certs ...*x509.Certificate) {
	data := new(bytes.Buffer)
	for _, cert := range certs {
		err := pem.Encode(data, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		checkErr(err)
	}
	writeFile(path, data.Bytes(), 0644)
}

func writeFile(path string, data []byte, mode os.FileMode) {
	err := ioutil.WriteFile(path, data, mode)
	checkErr(err)
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
