package trustbundlesources

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
)

func SetupTrustBundle(ac *agent.Config, bconfig *Config) error {
	// Either download the trust bundle if TrustBundleURL is set, or read it
	// from disk if TrustBundlePath is set
	ac.InsecureBootstrap = bconfig.InsecureBootstrap

	var bundleBytes []byte
	var err error

	switch {
	case bconfig.TrustBundleURL != "":
		bundleBytes, err = downloadTrustBundle(bconfig.TrustBundleURL, bconfig.TrustBundleUnixSocket)
		if err != nil {
			return err
		}
	case bconfig.TrustBundlePath != "":
		bundleBytes, err = loadTrustBundle(bconfig.TrustBundlePath)
		if err != nil {
			return fmt.Errorf("could not parse trust bundle: %w", err)
		}
	default:
		// If InsecureBootstrap is configured, the bundle is not required
		if bconfig.InsecureBootstrap {
			return nil
		}
	}

	bundle, err := parseTrustBundle(bundleBytes, bconfig.TrustBundleFormat)
	if err != nil {
		return err
	}

	if len(bundle) == 0 {
		return errors.New("no certificates found in trust bundle")
	}

	ac.TrustBundle = bundle

	return nil
}

func parseTrustBundle(bundleBytes []byte, trustBundleContentType string) ([]*x509.Certificate, error) {
	switch trustBundleContentType {
	case BundleFormatPEM:
		bundle, err := pemutil.ParseCertificates(bundleBytes)
		if err != nil {
			return nil, err
		}
		return bundle, nil
	case BundleFormatSPIFFE:
		bundle, err := bundleutil.Unmarshal(spiffeid.TrustDomain{}, bundleBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse SPIFFE trust bundle: %w", err)
		}
		return bundle.X509Authorities(), nil
	}

	return nil, fmt.Errorf("unknown trust bundle format: %s", trustBundleContentType)
}

func downloadTrustBundle(trustBundleURL string, trustBundleUnixSocket string) ([]byte, error) {
	var req *http.Request
	client := http.DefaultClient
	if trustBundleUnixSocket != "" {
		client = &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", trustBundleUnixSocket)
				},
			},
		}
	}
	req, err := http.NewRequest("GET", trustBundleURL, nil)
	if err != nil {
		return nil, err
	}

	// Download the trust bundle URL from the user specified URL
	// We use gosec -- the annotation below will disable a security check that URLs are not tainted
	/* #nosec G107 */
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch trust bundle URL %s: %w", trustBundleURL, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error downloading trust bundle: %s", resp.Status)
	}
	pemBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read from trust bundle URL %s: %w", trustBundleURL, err)
	}

	return pemBytes, nil
}

func loadTrustBundle(path string) ([]byte, error) {
	bundleBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return bundleBytes, nil
}
