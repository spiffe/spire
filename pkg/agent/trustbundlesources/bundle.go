package trustbundlesources

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/bundleutil"
)

type Bundle struct {
	config *Config
	use int
	connectionAttempts int
	startTime time.Time
}

//FIXME KMF take in state interface...
func New(config *Config) *Bundle {
	return &Bundle {
		config: config,
	}
}

func (b *Bundle) SetUse(use int) {
	if b.use != use {
		b.use = use
		b.connectionAttempts = 0
		b.startTime = time.Now()
	}
}

func (b *Bundle) SetSuccess() {
	b.use = UseUnspecified
	b.connectionAttempts = 0
	b.startTime = time.Time{}
	//FIXME clear out settings in the state store too
}

func (b *Bundle) GetStartTime() time.Time {
	return b.startTime
}

func (b *Bundle) GetBundle() ([]*x509.Certificate, error) {
	var bundleBytes []byte
	var err error

	switch {
	case b.config.TrustBundleURL != "":
		bundleBytes, err = downloadTrustBundle(b.config.TrustBundleURL)
		if err != nil {
			return nil, err
		}
	case b.config.TrustBundlePath != "":
		bundleBytes, err = loadTrustBundle(b.config.TrustBundlePath)
		if err != nil {
			return nil, fmt.Errorf("could not parse trust bundle: %w", err)
		}
	default:
		// If InsecureBootstrap is configured, the bundle is not required
		if b.config.InsecureBootstrap {
			return nil, nil
		}
	}

	bundle, err := parseTrustBundle(bundleBytes, b.config.TrustBundleFormat)
	if err != nil {
		return nil, err
	}

	if len(bundle) == 0 {
		return nil, errors.New("no certificates found in trust bundle")
	}

	return bundle, nil
}

func parseTrustBundle(bundleBytes []byte, trustBundleContentType string) ([]*x509.Certificate, error) {
	switch trustBundleContentType {
	case bundleFormatPEM:
		bundle, err := pemutil.ParseCertificates(bundleBytes)
		if err != nil {
			return nil, err
		}
		return bundle, nil
	case bundleFormatSPIFFE:
		bundle, err := bundleutil.Unmarshal(spiffeid.TrustDomain{}, bundleBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse SPIFFE trust bundle: %w", err)
		}
		return bundle.X509Authorities(), nil
	}

	return nil, fmt.Errorf("unknown trust bundle format: %s", trustBundleContentType)
}

func downloadTrustBundle(trustBundleURL string) ([]byte, error) {
	// Download the trust bundle URL from the user specified URL
	// We use gosec -- the annotation below will disable a security check that URLs are not tainted
	/* #nosec G107 */
	resp, err := http.Get(trustBundleURL)
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
