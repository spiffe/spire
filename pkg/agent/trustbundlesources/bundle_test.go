package trustbundlesources

import (
	"io"
	"os"
	"path"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
)

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
	}{
		{
			msg:                 "if URL is not found, should be an error",
			status:              http.StatusNotFound,
			fileContents:        "",
			format:              bundleFormatPEM,
			expectDownloadError: true,
			expectParseError:    false,
		},
		{
			msg:                 "if URL returns error 500, should be an error",
			status:              http.StatusInternalServerError,
			fileContents:        "",
			format:              bundleFormatPEM,
			expectDownloadError: true,
			expectParseError:    false,
		},
		{
			msg:                 "if file is not parseable, should be an error",
			status:              http.StatusOK,
			fileContents:        "NON PEM PARSEABLE TEXT HERE",
			format:              bundleFormatPEM,
			expectDownloadError: false,
			expectParseError:    true,
		},
		{
			msg:                 "if file is empty, should be an error",
			status:              http.StatusOK,
			fileContents:        "",
			format:              bundleFormatPEM,
			expectDownloadError: false,
			expectParseError:    true,
		},
		{
			msg:                 "if file is valid, should not be an error",
			status:              http.StatusOK,
			fileContents:        string(testTB),
			format:              bundleFormatPEM,
			expectDownloadError: false,
			expectParseError:    false,
		},
		{
			msg:                 "if file is not parseable, format is SPIFFE, should not be an error",
			status:              http.StatusOK,
			fileContents:        "[}",
			format:              bundleFormatSPIFFE,
			expectDownloadError: false,
			expectParseError:    true,
		},
		{
			msg:                 "if file is valid, format is SPIFFE, should not be an error",
			status:              http.StatusOK,
			fileContents:        testTBSPIFFE,
			format:              bundleFormatSPIFFE,
			expectDownloadError: false,
			expectParseError:    false,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.msg, func(t *testing.T) {
			testServer := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(testCase.status)
					_, _ = io.WriteString(w, testCase.fileContents)
					// if err != nil {
					// 	return
					// }
				}))
			defer testServer.Close()
			bundleBytes, err := downloadTrustBundle(testServer.URL, "")
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

