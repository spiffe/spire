package bundle

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/server/endpoints/bundle/internal/acmetest"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/memory"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	serverCertLifetime = time.Hour
)

func TestServer(t *testing.T) {
	serverCert, serverKey := createServerCertificate(t)

	// create a bundle for testing. we need a certificate in the bundle since
	// the root lifetimes are used to heuristically determine the refresh hint.
	// since the content doesn't really matter, we'll just add the server cert.
	bundle := bundleutil.New("spiffe://domain.test")
	bundle.AppendRootCA(serverCert)

	// even though this will be SPIFFE authentication in production, there is
	// no functional change in the code based on the server certificate
	// returned from the getter, so for test purposes we'll just use a
	// localhost certificate.
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(serverCert)
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: rootCAs,
			},
		},
	}

	testCases := []struct {
		name       string
		method     string
		path       string
		status     int
		body       string
		bundle     *bundleutil.Bundle
		serverCert *x509.Certificate
		reqErr     string
	}{
		{
			name:   "success",
			method: "GET",
			path:   "/",
			status: http.StatusOK,
			body: fmt.Sprintf(`{
				"keys": [
					{
						"crv":"P-256",
						"kty":"EC",
						"use":"x509-svid",
						"x":"kkEn5E2Hd_rvCRDCVMNj3deN0ADij9uJVmN-El0CJz0",
						"y":"qNrnjhtzrtTR0bRgI2jPIC1nEgcWNX63YcZOEzyo1iA",
						"x5c": [%q]
					}
				],
				"spiffe_refresh_hint": 360
			}`, base64.StdEncoding.EncodeToString(serverCert.Raw)),
			bundle:     bundle,
			serverCert: serverCert,
		},
		{
			name:       "invalid method",
			method:     "POST",
			path:       "/",
			status:     http.StatusMethodNotAllowed,
			body:       "405 method not allowed\n",
			serverCert: serverCert,
		},
		{
			name:       "invalid path",
			method:     "GET",
			path:       "/foo",
			status:     http.StatusNotFound,
			body:       "404 page not found\n",
			serverCert: serverCert,
		},
		{
			name:       "fail to retrieve bundle",
			method:     "GET",
			path:       "/",
			status:     http.StatusInternalServerError,
			body:       "500 unable to retrieve local bundle\n",
			serverCert: serverCert,
		},
		{
			name:   "fail to get server creds",
			reqErr: "remote error: tls: internal error",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			addr, done := newTestServer(t,
				testGetter(testCase.bundle),
				testSPIFFEAuth(testCase.serverCert, serverKey),
			)
			defer done()

			// form and make the request
			req, err := http.NewRequest(testCase.method, fmt.Sprintf("https://%s%s", addr, testCase.path), nil)
			require.NoError(t, err)
			resp, err := client.Do(req)
			if testCase.reqErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), testCase.reqErr)
				return
			}
			require.NoError(t, err)
			defer resp.Body.Close()

			actual, err := ioutil.ReadAll(resp.Body)
			require.NoError(t, err)

			require.Equal(t, testCase.status, resp.StatusCode)
			if testCase.status == http.StatusOK {
				// we expect a JSON payload for 200
				require.JSONEq(t, testCase.body, string(actual))
			} else {
				require.Equal(t, testCase.body, string(actual))
			}
		})
	}
}

func TestACMEAuth(t *testing.T) {
	dir, err := ioutil.TempDir("", "spire-server-endpoints-bundle-acme-")
	require.NoError(t, err)

	bundle := bundleutil.New("spiffe://domain.test")
	km := memory.New()

	ca := acmetest.NewCAServer([]string{"tls-alpn-01"}, []string{"domain.test"})

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    ca.Roots,
				ServerName: "domain.test",
			},
		},
	}

	// Perform the initial challenge to obtain a new certificate but without
	// the TOS being accepted. This should fail. We require the ToSAccepted
	// configurable to be set in order to funcion.
	t.Run("new-account-tos-not-accepted", func(t *testing.T) {
		log, hook := test.NewNullLogger()
		addr, done := newTestServer(t, testGetter(bundle),
			ACMEAuth(log, km, ACMEConfig{
				DirectoryURL: ca.URL,
				DomainName:   "domain.test",
				CacheDir:     dir,
				Email:        "admin@domain.test",
				ToSAccepted:  false,
			}),
		)
		defer done()

		ca.Resolve("domain.test", addr.String())

		// Request should fail since the challenge to obtain a certificate
		// will not proceed if the TOS has not been accepted.
		_, err := client.Get(fmt.Sprintf("https://%s", addr)) //nolint: bodyclose // request should fail so no body to close
		require.Error(t, err)

		if entry := hook.LastEntry(); assert.NotNil(t, entry) {
			assert.Equal(t, "ACME Terms of Service have not been accepted. See the `tos_accepted` configurable.", entry.Message)
			assert.Equal(t, logrus.WarnLevel, entry.Level)
			assert.Equal(t, logrus.Fields{
				"directory_url": ca.URL,
				"tos_url":       ca.URL + "/tos",
				"email":         "admin@domain.test",
			}, entry.Data)
		}
	})

	// Perform the initial challenge to obtain a new certificate.
	t.Run("initial", func(t *testing.T) {
		log, hook := test.NewNullLogger()
		addr, done := newTestServer(t, testGetter(bundle),
			ACMEAuth(log, km, ACMEConfig{
				DirectoryURL: ca.URL,
				DomainName:   "domain.test",
				CacheDir:     dir,
				Email:        "admin@domain.test",
				ToSAccepted:  true,
			}),
		)
		defer done()

		ca.Resolve("domain.test", addr.String())

		resp, err := client.Get(fmt.Sprintf("https://%s", addr))
		require.NoError(t, err)
		resp.Body.Close()

		// Assert that the keystore has been populated with the account
		// key and cert key for the domain.
		keys, err := km.GetPublicKeys(context.Background(), &keymanager.GetPublicKeysRequest{})
		require.NoError(t, err)
		if assert.Len(t, keys.PublicKeys, 2) {
			assert.Equal(t, "bundle-acme-acme_account+key", keys.PublicKeys[0].Id)
			assert.Equal(t, "bundle-acme-domain.test", keys.PublicKeys[1].Id)
		}

		// Make sure we logged the ToS details
		if entry := hook.LastEntry(); assert.NotNil(t, entry) {
			assert.Equal(t, "ACME Terms of Service accepted", entry.Message)
			assert.Equal(t, logrus.InfoLevel, entry.Level)
			assert.Equal(t, logrus.Fields{
				"directory_url": ca.URL,
				"tos_url":       ca.URL + "/tos",
				"email":         "admin@domain.test",
			}, entry.Data)
		}
	})

	// Now test that the cached credentials are used. This test resolves the
	// domain to bogus address so that the challenge would fail if it were tried
	// as a way of telling that the challenge was not attempted
	t.Run("cached", func(t *testing.T) {
		log, _ := test.NewNullLogger()
		addr, done := newTestServer(t, testGetter(bundle),
			ACMEAuth(log, km, ACMEConfig{
				DirectoryURL: ca.URL,
				DomainName:   "domain.test",
				CacheDir:     dir,
				Email:        "admin@domain.test",
				ToSAccepted:  true,
			}),
		)
		defer done()

		ca.Resolve("domain.test", "127.0.0.1:0")

		resp, err := client.Get(fmt.Sprintf("https://%s", addr))
		require.NoError(t, err)
		resp.Body.Close()
	})
}

func newTestServer(t *testing.T, getter Getter, serverAuth ServerAuth) (net.Addr, func()) {
	ctx, cancel := context.WithCancel(context.Background())

	addrCh := make(chan net.Addr, 1)
	listen := func(network, address string) (net.Listener, error) {
		listener, err := net.Listen(network, address)
		if err != nil {
			return nil, err
		}
		addrCh <- listener.Addr()
		return listener, nil
	}

	log, _ := test.NewNullLogger()
	server := NewServer(ServerConfig{
		Log:        log,
		Address:    "localhost:0",
		Getter:     getter,
		ServerAuth: serverAuth,
		listen:     listen,
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe(ctx)
	}()

	// wait for the listener to be created and the url to be set
	var addr net.Addr
	select {
	case addr = <-addrCh:
	case err := <-errCh:
		cancel()
		require.NoError(t, err, "unexpected error while waiting for url")
	case <-time.After(time.Minute):
		cancel()
		require.FailNow(t, "timed out waiting for url")
	}

	return addr, cancel
}

func testGetter(bundle *bundleutil.Bundle) Getter {
	return GetterFunc(func(ctx context.Context) (*bundleutil.Bundle, error) {
		if bundle == nil {
			return nil, errors.New("no bundle configured")
		}
		return bundle, nil
	})
}

func testSPIFFEAuth(cert *x509.Certificate, key crypto.Signer) ServerAuth {
	return SPIFFEAuth(func() ([]*x509.Certificate, crypto.PrivateKey, error) {
		if cert == nil {
			return nil, nil, errors.New("no server certificate")
		}
		return []*x509.Certificate{cert}, key, nil
	})
}

func createServerCertificate(t *testing.T) (*x509.Certificate, crypto.Signer) {
	now := time.Now()
	return spiretest.SelfSignCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    now,
		NotAfter:     now.Add(serverCertLifetime),
		URIs:         []*url.URL{idutil.ServerURI("domain.test")},
	})
}
