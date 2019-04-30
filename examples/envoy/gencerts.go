package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
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
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gencerts NAME1 [NAME2...]")
		os.Exit(1)
	}

	caKey := generateRSAKey()
	caCert := createRootCertificate(caKey, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotAfter:              neverExpires,
		Subject:               pkix.Name{CommonName: "agent CA"},
	})

	writeCerts(filepath.Join("docker", "spire-server", "conf", "agent-cacert.pem"), caCert)

	for _, name := range os.Args[1:] {
		agentKey := generateRSAKey()
		agentCert := createCertificate(agentKey, &x509.Certificate{
			SerialNumber: big.NewInt(1),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			NotAfter:     neverExpires,
			Subject:      pkix.Name{CommonName: fmt.Sprintf("%s agent", name)},
		}, caKey, caCert)

		dir := filepath.Join("docker", name, "conf")
		writeKey(filepath.Join(dir, "agent.key.pem"), agentKey)
		writeCerts(filepath.Join(dir, "agent.crt.pem"), agentCert)

		fingerprint := sha1.Sum(agentCert.Raw)
		fmt.Printf("%x %s\n", fingerprint, name)
	}
}

func createRootCertificate(key *rsa.PrivateKey, tmpl *x509.Certificate) *x509.Certificate {
	return createCertificate(key, tmpl, key, tmpl)
}

func createCertificate(key *rsa.PrivateKey, tmpl *x509.Certificate, parentKey *rsa.PrivateKey, parent *x509.Certificate) *x509.Certificate {
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	checkErr(err)
	cert, err := x509.ParseCertificate(certDER)
	checkErr(err)
	return cert
}

func generateRSAKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 768)
	checkErr(err)
	return key
}

func writeKey(path string, key interface{}) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	checkErr(err)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})
	err = ioutil.WriteFile(path, pemBytes, 0600)
	checkErr(err)
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
	err := ioutil.WriteFile(path, data.Bytes(), 0644)
	checkErr(err)
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
