package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/stretchr/testify/require"
)

var (
	testKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu4d/KpV4RMNNr8I6
czfmH5spJ0LK1r8P8WnkuRZMNDyhRANCAARSUEgB5UlimKzT4TOBs/Dhh3oDF8kr
xrHoko3NlsLMmZn282gMYb+0Au9R+IXllaYy8+vuW9R7VctQwmaAgGU4
-----END PRIVATE KEY-----`)

	testKey, _ = pemutil.ParseSigner(testKeyPEM)
)

func TestServer(t *testing.T) {
	dir, err := ioutil.TempDir("", "k8s-workload-registrar-server-")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	keyPath := filepath.Join(dir, "key.pem")
	certPath := filepath.Join(dir, "cert.pem")
	caCertPath := filepath.Join(dir, "cacert.pem")
	badPath := filepath.Join(dir, "bad")

	serverCert := createServerCertificate(t)
	clientCert := createClientCertificate(t)

	writeFile(t, keyPath, testKeyPEM, 0600)
	writeCertPEM(t, certPath, serverCert)
	writeCertPEM(t, caCertPath, clientCert)

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(serverCert)

	testCases := []struct {
		name   string
		config ServerConfig
		cert   *x509.Certificate
		newErr string
		reqErr string
	}{
		{
			name: "bad addr",
			config: ServerConfig{
				Addr:                           "this is not a good addr",
				CertPath:                       certPath,
				KeyPath:                        keyPath,
				CaCertPath:                     caCertPath,
				InsecureSkipClientVerification: false,
			},
			newErr: "unable to listen",
		},
		{
			name: "bad cert",
			config: ServerConfig{
				Addr:                           "localhost:0",
				CertPath:                       badPath,
				KeyPath:                        keyPath,
				CaCertPath:                     caCertPath,
				InsecureSkipClientVerification: false,
			},
			newErr: "unable to load server keypair",
		},
		{
			name: "bad key",
			config: ServerConfig{
				Addr:                           "localhost:0",
				CertPath:                       certPath,
				KeyPath:                        badPath,
				CaCertPath:                     caCertPath,
				InsecureSkipClientVerification: false,
			},
			newErr: "unable to load server keypair",
		},
		{
			name: "bad cacert",
			config: ServerConfig{
				Addr:                           "localhost:0",
				CertPath:                       certPath,
				KeyPath:                        keyPath,
				CaCertPath:                     badPath,
				InsecureSkipClientVerification: false,
			},
			newErr: "unable to read cacert file",
		},
		{
			name: "fails over TLS",
			config: ServerConfig{
				Addr:                           "localhost:0",
				CertPath:                       certPath,
				KeyPath:                        keyPath,
				CaCertPath:                     caCertPath,
				InsecureSkipClientVerification: false,
			},
			reqErr: "remote error: tls: bad certificate",
		},
		{
			name: "success over TLS when verification skipped",
			config: ServerConfig{
				Addr:                           "localhost:0",
				CertPath:                       certPath,
				KeyPath:                        keyPath,
				CaCertPath:                     caCertPath,
				InsecureSkipClientVerification: true,
			},
		},
		{
			name: "fails over mTLS with bad cert",
			cert: serverCert,
			config: ServerConfig{
				Addr:                           "localhost:0",
				CertPath:                       certPath,
				KeyPath:                        keyPath,
				CaCertPath:                     caCertPath,
				InsecureSkipClientVerification: false,
			},
			reqErr: "remote error: tls: bad certificate",
		},
		{
			name: "success over mTLS",
			cert: clientCert,
			config: ServerConfig{
				Addr:                           "localhost:0",
				CertPath:                       certPath,
				KeyPath:                        keyPath,
				CaCertPath:                     caCertPath,
				InsecureSkipClientVerification: false,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			log, _ := logtest.NewNullLogger()

			// prepare the config
			config := testCase.config
			config.Log = log
			config.Handler = http.HandlerFunc(echoHandler)

			// initialize the server
			server, err := NewServer(config)
			if !checkErr(t, err, testCase.newErr) {
				return
			}

			// set up the transport
			transport := &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: rootCAs,
				},
				TLSHandshakeTimeout: time.Second * 10,
			}
			if testCase.cert != nil {
				transport.TLSClientConfig.Certificates = []tls.Certificate{
					{
						Certificate: [][]byte{testCase.cert.Raw},
						PrivateKey:  testKey,
					},
				}
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go server.Run(ctx)

			// do the request
			client := http.Client{
				Transport: transport,
			}
			resp, err := client.Post(fmt.Sprintf("https://%s", server.Addr()), "", strings.NewReader("Hello"))
			if !checkErr(t, err, testCase.reqErr) {
				return
			}
			defer resp.Body.Close()

			// assert the response which shows the handler was wired up
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			require.Equal(t, "Hello", buf.String())
		})
	}
}

func createClientCertificate(t *testing.T) *x509.Certificate {
	return createCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotAfter:     time.Now().Add(time.Hour),
	})
}

func createServerCertificate(t *testing.T) *x509.Certificate {
	return createCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotAfter:    time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	})
}

func createCertificate(t *testing.T, tmpl *x509.Certificate) *x509.Certificate {
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, testKey.Public(), testKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

func writeCertPEM(t *testing.T, path string, cert *x509.Certificate) {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	writeFile(t, path, certPEM, 0644)
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	err := ioutil.WriteFile(path, data, mode)
	require.NoError(t, err)
}

func checkErr(t *testing.T, err error, expected string) bool {
	if expected == "" {
		require.NoError(t, err)
		return true
	} else {
		require.Error(t, err)
		require.Contains(t, err.Error(), expected)
		return false
	}
}

func echoHandler(w http.ResponseWriter, req *http.Request) {
	io.Copy(w, req.Body)
}
