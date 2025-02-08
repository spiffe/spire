package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
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
		SerialNumber:          big.NewInt(0x1a2b3c),
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotAfter:              neverExpires,
	})

	intermediateKey := generateRSAKey()

	intermediateCert := createCertificate(intermediateKey, &x509.Certificate{
		SerialNumber:          big.NewInt(0x4d5e6f),
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotAfter:              neverExpires,
	}, rootKey, rootCert)

	leafKey := generateRSAKey()

	leafCert := createCertificate(leafKey, &x509.Certificate{
		SerialNumber: big.NewInt(0x0a1b2c3d4e5f),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotAfter:     neverExpires,
		Subject:      pkix.Name{CommonName: "COMMONNAME"},
		URIs: []*url.URL{
			{Scheme: "x509pop", Host: "example.org", Path: "/datacenter/us-east-1"},
			{Scheme: "x509pop", Host: "example.org", Path: "/environment/production"},
			{Scheme: "x509pop", Host: "example.org", Path: "/key/path/to/value"},
		},
	}, intermediateKey, intermediateCert)

	svid, _ := url.Parse("spiffe://example.org/somesvid")
	spiffeLeafCertReg := createCertificate(leafKey, &x509.Certificate{
		SerialNumber: big.NewInt(0x0a1b2c3d4e6f),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotAfter:     neverExpires,
		Subject:      pkix.Name{CommonName: "COMMONNAME"},
		URIs:         []*url.URL{svid},
	}, intermediateKey, intermediateCert)

	svidExchange, _ := url.Parse("spiffe://example.org/spire-exchange/testhost")
	spiffeLeafCertExchange := createCertificate(leafKey, &x509.Certificate{
		SerialNumber: big.NewInt(0x0a1b2c3d4e7f),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotAfter:     neverExpires,
		Subject:      pkix.Name{CommonName: "COMMONNAME"},
		URIs: []*url.URL{
			svidExchange,
			{Scheme: "x509pop", Host: "example.org", Path: "/datacenter/us-east-1"},
			{Scheme: "x509pop", Host: "example.org", Path: "/environment/production"},
			{Scheme: "x509pop", Host: "example.org", Path: "/key/path/to/value"},
		},
	}, intermediateKey, intermediateCert)

	writeKey("leaf-key.pem", leafKey)
	writeCerts("leaf-crt-bundle.pem", leafCert, intermediateCert)
	writeCerts("leaf.pem", leafCert)
	writeCerts("intermediate.pem", intermediateCert)
	writeCerts("root-crt.pem", rootCert)
	writeCerts("svidreg.pem", spiffeLeafCertReg, intermediateCert)
	writeCerts("svidexchange.pem", spiffeLeafCertExchange, intermediateCert)
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
	key, err := rsa.GenerateKey(rand.Reader, 768) //nolint: gosec // small key is to keep test fast... not a security feature
	panice(err)
	return key
}

func writeKey(path string, key any) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	panice(err)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})
	err = os.WriteFile(path, pemBytes, 0o600)
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
	err := os.WriteFile(path, data.Bytes(), 0o600)
	panice(err)
}
