package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/spiffe/spire/pkg/common/pemutil"
)

func main() {
	rootKey := generateKey()
	serverKey := generateKey()
	clientKey := generateKey()

	notAfter := time.Now().Add(time.Hour * 24 * 365 * 10)

	rootCert := createCertificate(&x509.Certificate{
		SerialNumber:          big.NewInt(1),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		NotAfter:              notAfter,
	}, nil, rootKey, nil)

	serverCert := createCertificate(&x509.Certificate{
		SerialNumber:   big.NewInt(2),
		NotAfter:       notAfter,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1)},
		AuthorityKeyId: rootCert.SubjectKeyId,
	}, rootCert, serverKey, rootKey)

	clientCert := createCertificate(&x509.Certificate{
		SerialNumber:   big.NewInt(3),
		NotAfter:       notAfter,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		AuthorityKeyId: rootCert.SubjectKeyId,
	}, rootCert, clientKey, rootKey)

	writeFile("root-cert.pem", certPEM(rootCert))
	writeFile("server-cert.pem", certPEM(serverCert))
	writeFile("server-key.pem", keyPEM(serverKey))
	writeFile("client-cert.pem", certPEM(clientCert))
	writeFile("client-key.pem", keyPEM(clientKey))
}

func generateKey() crypto.Signer {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	checkErr(err)
	return key
}

func createCertificate(tmpl, parent *x509.Certificate, key, parentKey crypto.Signer) *x509.Certificate {
	if parent == nil {
		parent = tmpl
		parentKey = key
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	checkErr(err)
	cert, err := x509.ParseCertificate(certDER)
	checkErr(err)
	return cert
}

func keyPEM(key crypto.Signer) []byte {
	data, err := pemutil.EncodePKCS8PrivateKey(key)
	checkErr(err)
	return data
}

func certPEM(certs ...*x509.Certificate) []byte {
	return pemutil.EncodeCertificates(certs)
}

func writeFile(path string, data []byte) {
	err := os.WriteFile(path, data, 0600)
	checkErr(err)
}

func checkErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
