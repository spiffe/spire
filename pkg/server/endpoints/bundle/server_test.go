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

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/test/spiretest"
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
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			urlCh := make(chan string, 1)
			listen := func(network, address string) (net.Listener, error) {
				listener, err := net.Listen(network, address)
				if err != nil {
					return nil, err
				}
				urlCh <- fmt.Sprintf("https://%s%s", listener.Addr(), testCase.path)
				return listener, nil
			}

			log, _ := test.NewNullLogger()
			server := NewServer(ServerConfig{
				Log:          log,
				Address:      "localhost:0",
				BundleGetter: testBundleGetter(testCase.bundle),
				CredsGetter:  testServerCredsGetter(testCase.serverCert, serverKey),
				listen:       listen,
			})

			errCh := make(chan error, 1)
			go func() {
				errCh <- server.Run(ctx)
			}()

			// wait for the listener to be created and the url to be set
			var url string
			select {
			case url = <-urlCh:
			case err := <-errCh:
				require.NoError(t, err, "unexpected error while waiting for url")
			case <-time.After(time.Minute):
				require.FailNow(t, "timed out waiting for url")
			}

			// form and make the request
			req, err := http.NewRequest(testCase.method, url, nil)
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

func testBundleGetter(bundle *bundleutil.Bundle) BundleGetter {
	return BundleGetterFunc(func(ctx context.Context) (*bundleutil.Bundle, error) {
		if bundle == nil {
			return nil, errors.New("no bundle configured")
		}
		return bundle, nil
	})
}

func testServerCredsGetter(cert *x509.Certificate, key crypto.Signer) ServerCredsGetter {
	return ServerCredsGetterFunc(func() ([]*x509.Certificate, crypto.PrivateKey, error) {
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
