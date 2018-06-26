package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"time"
)

func panice(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	// The "never expires" timestamp from RFC5280
	neverExpires := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

	rootKey := generateRSAKey()

	rootCert := createRootCertificate(rootKey, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		BasicConstraintsValid: true,
		IsCA:     true,
		NotAfter: neverExpires,
	})

	intermediateKey := generateRSAKey()

	intermediateCert := createCertificate(intermediateKey, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		BasicConstraintsValid: true,
		IsCA:     true,
		NotAfter: neverExpires,
	}, rootKey, rootCert)

	leafKey := generateRSAKey()

	leafCert := createCertificate(leafKey, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotAfter:     neverExpires,
	}, intermediateKey, intermediateCert)

	writeKey("leaf-key.pem", leafKey)
	writeCerts("leaf-crt-bundle.pem", leafCert, intermediateCert)
	writeCerts("root-crt.pem", rootCert)
}

func createRootCertificate(key *rsa.PrivateKey, tmpl *x509.Certificate) *x509.Certificate {
	return createCertificate(key, tmpl, key, tmpl)
}

func createCertificate(key *rsa.PrivateKey, tmpl *x509.Certificate, parentKey *rsa.PrivateKey, parent *x509.Certificate) *x509.Certificate {
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	panice(err)
	cert, err := x509.ParseCertificate(certDER)
	panice(err)
	return cert
}

func generateRSAKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 768)
	panice(err)
	return key
}

func writeKey(path string, key interface{}) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	panice(err)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})
	err = ioutil.WriteFile(path, pemBytes, 0600)
	panice(err)
}

func writeCerts(path string, certs ...*x509.Certificate) {
	data := new(bytes.Buffer)
	for _, cert := range certs {
		err := pem.Encode(data, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		panice(err)
	}
	err := ioutil.WriteFile(path, data.Bytes(), 0644)
	panice(err)
}
