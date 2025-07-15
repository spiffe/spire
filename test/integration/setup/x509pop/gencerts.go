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
	"flag"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type stringArrayFlag []string

func (s *stringArrayFlag) String() string {
	return strings.Join(*s, ";")
}

func (s *stringArrayFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	var trustDomain string
	var x509popSans stringArrayFlag
	flag.StringVar(&trustDomain, "trust-domain", "", "Name of the trust domains the certs will be used for")
	flag.Var(&x509popSans, "x509pop-san", "Uri san to set using x509pop:// scheme")

	flag.Parse()

	if len(flag.Args()) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gencerts SERVERDIR AGENTDIR [AGENTDIR...]")
		os.Exit(1)
	}

	var x509popSanUris []*url.URL
	for _, x509popSan := range x509popSans {
		san, err := url.Parse("x509pop://" + trustDomain + "/" + x509popSan)
		checkErr(err)
		x509popSanUris = append(x509popSanUris, san)
	}

	notAfter := time.Now().Add(time.Hour)

	caKey := generateKey()
	caCert := createRootCertificate(caKey, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotAfter:              notAfter,
		Subject:               pkix.Name{CommonName: "Agent CA"},
	})

	writeCerts(filepath.Join(flag.Arg(0), "agent-cacert.pem"), caCert)

	for i, dir := range flag.Args()[1:] {
		agentKey := generateKey()
		agentCert := createCertificate(agentKey, &x509.Certificate{
			SerialNumber: big.NewInt(int64(i)),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			NotAfter:     notAfter,
			Subject:      pkix.Name{CommonName: filepath.Base(dir)},
			URIs:         x509popSanUris,
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
	writeFile(path, pemBytes, 0o644) // This key is used only for testing purposes.
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
	writeFile(path, data.Bytes(), 0o644)
}

func writeFile(path string, data []byte, mode os.FileMode) {
	err := os.WriteFile(path, data, mode)
	checkErr(err)
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
