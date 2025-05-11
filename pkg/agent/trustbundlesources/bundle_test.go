package trustbundlesources

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
)

func TestGetBundle(t *testing.T) {
	testTrustBundlePath := path.Join(util.ProjectRoot(), "conf/agent/dummy_root_ca.crt")
	testTBSPIFFE := `{
    "keys": [
        {
            "use": "x509-svid",
            "kty": "EC",
            "crv": "P-384",
            "x": "WjB-nSGSxIYiznb84xu5WGDZj80nL7W1c3zf48Why0ma7Y7mCBKzfQkrgDguI4j0",
            "y": "Z-0_tDH_r8gtOtLLrIpuMwWHoe4vbVBFte1vj6Xt6WeE8lXwcCvLs_mcmvPqVK9j",
            "x5c": [
                "MIIBzDCCAVOgAwIBAgIJAJM4DhRH0vmuMAoGCCqGSM49BAMEMB4xCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZTUElGRkUwHhcNMTgwNTEzMTkzMzQ3WhcNMjMwNTEyMTkzMzQ3WjAeMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGU1BJRkZFMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEWjB+nSGSxIYiznb84xu5WGDZj80nL7W1c3zf48Why0ma7Y7mCBKzfQkrgDguI4j0Z+0/tDH/r8gtOtLLrIpuMwWHoe4vbVBFte1vj6Xt6WeE8lXwcCvLs/mcmvPqVK9jo10wWzAdBgNVHQ4EFgQUh6XzV6LwNazA+GTEVOdu07o5yOgwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwGQYDVR0RBBIwEIYOc3BpZmZlOi8vbG9jYWwwCgYIKoZIzj0EAwQDZwAwZAIwE4Me13qMC9i6Fkx0h26y09QZIbuRqA9puLg9AeeAAyo5tBzRl1YL0KNEp02VKSYJAjBdeJvqjJ9wW55OGj1JQwDFD7kWeEB6oMlwPbI/5hEY3azJi16I0uN1JSYTSWGSqWc="
            ]
        }
    ]
}`
	cases := []struct {
		msg               string
		insecureBootstrap bool
		error             bool
		trustBundlePath   string
		trustBundleFormat string
		trustBundleURL    bool
		trustBundleSocket string
	}{
		{
			msg:               "insecure mode",
			insecureBootstrap: true,
			error:             false,
		},
		{
			msg:               "from file",
			insecureBootstrap: false,
			error:             false,
			trustBundlePath:   testTrustBundlePath,
			trustBundleFormat: BundleFormatPEM,
		},
		{
			msg:               "from file wrong format",
			insecureBootstrap: false,
			error:             true,
			trustBundlePath:   testTrustBundlePath,
			trustBundleFormat: BundleFormatSPIFFE,
		},
		{
			msg:               "from file that doesn't exist",
			insecureBootstrap: false,
			error:             true,
			trustBundlePath:   "doesnotexist",
			trustBundleFormat: BundleFormatPEM,
		},
		{
			msg:               "from url ok",
			insecureBootstrap: false,
			error:             false,
			trustBundleURL:    true,
			trustBundleFormat: BundleFormatSPIFFE,
		},
		{
			msg:               "from url socket, fail",
			insecureBootstrap: false,
			error:             true,
			trustBundleURL:    true,
			trustBundleFormat: BundleFormatSPIFFE,
			trustBundleSocket: "doesnotexist",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.msg, func(t *testing.T) {
			var err error
			c := Config{
				InsecureBootstrap:     testCase.insecureBootstrap,
				TrustBundlePath:       testCase.trustBundlePath,
				TrustBundleFormat:     testCase.trustBundleFormat,
				TrustBundleUnixSocket: testCase.trustBundleSocket,
			}
			testServer := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, _ = io.WriteString(w, testTBSPIFFE)
				}))
			if testCase.trustBundleURL {
				c.TrustBundleURL = testServer.URL
			}
			log, _ := test.NewNullLogger()
			tbs := New(&c, log)
			require.NoError(t, err)

			trustBundle, insecureBootstrap, err := tbs.GetBundle()
			if testCase.error {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, insecureBootstrap, testCase.insecureBootstrap)
				if testCase.trustBundlePath != "" {
					require.Equal(t, len(trustBundle), 1)
				}
			}
		})
	}
}

func TestDownloadTrustBundle(t *testing.T) {
	testTB, _ := os.ReadFile(path.Join(util.ProjectRoot(), "conf/agent/dummy_root_ca.crt"))
	testTBSPIFFE := `{
    "keys": [
        {
            "use": "x509-svid",
            "kty": "EC",
            "crv": "P-384",
            "x": "WjB-nSGSxIYiznb84xu5WGDZj80nL7W1c3zf48Why0ma7Y7mCBKzfQkrgDguI4j0",
            "y": "Z-0_tDH_r8gtOtLLrIpuMwWHoe4vbVBFte1vj6Xt6WeE8lXwcCvLs_mcmvPqVK9j",
            "x5c": [
                "MIIBzDCCAVOgAwIBAgIJAJM4DhRH0vmuMAoGCCqGSM49BAMEMB4xCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZTUElGRkUwHhcNMTgwNTEzMTkzMzQ3WhcNMjMwNTEyMTkzMzQ3WjAeMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGU1BJRkZFMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEWjB+nSGSxIYiznb84xu5WGDZj80nL7W1c3zf48Why0ma7Y7mCBKzfQkrgDguI4j0Z+0/tDH/r8gtOtLLrIpuMwWHoe4vbVBFte1vj6Xt6WeE8lXwcCvLs/mcmvPqVK9jo10wWzAdBgNVHQ4EFgQUh6XzV6LwNazA+GTEVOdu07o5yOgwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwGQYDVR0RBBIwEIYOc3BpZmZlOi8vbG9jYWwwCgYIKoZIzj0EAwQDZwAwZAIwE4Me13qMC9i6Fkx0h26y09QZIbuRqA9puLg9AeeAAyo5tBzRl1YL0KNEp02VKSYJAjBdeJvqjJ9wW55OGj1JQwDFD7kWeEB6oMlwPbI/5hEY3azJi16I0uN1JSYTSWGSqWc="
            ]
        }
    ]
}`

	cases := []struct {
		msg                 string
		status              int
		fileContents        string
		format              string
		expectDownloadError bool
		expectParseError    bool
		unixSocket          bool
	}{
		{
			msg:                 "if URL is not found, should be an error",
			status:              http.StatusNotFound,
			fileContents:        "",
			format:              BundleFormatPEM,
			expectDownloadError: true,
			expectParseError:    false,
			unixSocket:          false,
		},
		{
			msg:                 "if URL returns error 500, should be an error",
			status:              http.StatusInternalServerError,
			fileContents:        "",
			format:              BundleFormatPEM,
			expectDownloadError: true,
			expectParseError:    false,
			unixSocket:          false,
		},
		{
			msg:                 "if file is not parseable, should be an error",
			status:              http.StatusOK,
			fileContents:        "NON PEM PARSEABLE TEXT HERE",
			format:              BundleFormatPEM,
			expectDownloadError: false,
			expectParseError:    true,
			unixSocket:          false,
		},
		{
			msg:                 "if file is empty, should be an error",
			status:              http.StatusOK,
			fileContents:        "",
			format:              BundleFormatPEM,
			expectDownloadError: false,
			expectParseError:    true,
			unixSocket:          false,
		},
		{
			msg:                 "if file is valid, should not be an error",
			status:              http.StatusOK,
			fileContents:        string(testTB),
			format:              BundleFormatPEM,
			expectDownloadError: false,
			expectParseError:    false,
			unixSocket:          false,
		},
		{
			msg:                 "if file is not parseable, format is SPIFFE, should not be an error",
			status:              http.StatusOK,
			fileContents:        "[}",
			format:              BundleFormatSPIFFE,
			expectDownloadError: false,
			expectParseError:    true,
			unixSocket:          false,
		},
		{
			msg:                 "if file is valid, format is SPIFFE, should not be an error",
			status:              http.StatusOK,
			fileContents:        testTBSPIFFE,
			format:              BundleFormatSPIFFE,
			expectDownloadError: false,
			expectParseError:    false,
			unixSocket:          false,
		},
		{
			msg:                 "if file is valid, format is SPIFFE, unix socket true, should not be an error",
			status:              http.StatusOK,
			fileContents:        testTBSPIFFE,
			format:              BundleFormatSPIFFE,
			expectDownloadError: false,
			expectParseError:    false,
			unixSocket:          true,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.msg, func(t *testing.T) {
			var unixSocket string
			var err error
			var bundleBytes []byte
			if testCase.unixSocket {
				tempDir, err := os.MkdirTemp("", "my-temp-dir-*")
				require.NoError(t, err)
				defer os.RemoveAll(tempDir)
				unixSocket = filepath.Join(tempDir, "socket")
			}
			testServer := httptest.NewUnstartedServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(testCase.status)
					_, _ = io.WriteString(w, testCase.fileContents)
					// if err != nil {
					// 	return
					// }
				}))
			if testCase.unixSocket {
				testServer.Listener, err = net.Listen("unix", unixSocket)
				require.NoError(t, err)
				testServer.Start()
				bundleBytes, err = downloadTrustBundle("http://localhost/trustbundle", unixSocket)
			} else {
				testServer.Start()
				bundleBytes, err = downloadTrustBundle(testServer.URL, "")
			}
			if testCase.expectDownloadError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				_, err := parseTrustBundle(bundleBytes, testCase.format)
				if testCase.expectParseError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
			}
		})
	}
}
