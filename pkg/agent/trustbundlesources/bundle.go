package trustbundlesources

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/storage"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
)

type Bundle struct {
	config             *Config
	use                int
	connectionAttempts int
	startTime          time.Time
	log                logrus.FieldLogger
	storage            storage.Storage
	lastBundle         []*x509.Certificate
}

// FIXME KMF take in state interface...
func New(config *Config, log logrus.FieldLogger) *Bundle {
	return &Bundle{
		config: config,
		log:    log,
	}
}

func (b *Bundle) SetStorage(storage storage.Storage) error {
	b.storage = storage
	use, startTime, err := b.storage.LoadBootstrapState()
	b.use = use
	b.startTime = startTime
	if use == UseUnspecified {
		use = UseBootstrap
	}
	return err
}

func (b *Bundle) SetUse(use int) error {
	if b.use != use {
		b.use = use
		b.connectionAttempts = 0
		b.startTime = time.Now()
		b.log.Info("Setting use.")
		err := b.storage.StoreBootstrapState(use, b.startTime)
		if err != nil {
			return err
		}
		/*
			only when after timeout....
			err := b.storage.StoreBundle(nil)
			//FIXME if svid is set, clear that too
		*/
		return err
	}
	return nil
}

func (b *Bundle) SetSuccessIfRunning() error {
	if !b.startTime.IsZero() {
		return b.SetSuccess()
	}
	return nil
}

func (b *Bundle) SetSuccess() error {
	var err error
	b.log.Info("Success, attempts=", b.connectionAttempts)
	b.use = UseRebootstrap
	b.connectionAttempts = 0
	b.startTime = time.Time{}
	b.log.Info("Setting use.")
	if b.storage != nil {
		err := b.storage.StoreBootstrapState(b.use, b.startTime)
		if err != nil {
			return err
		}
		err = b.storage.StoreBundle(b.lastBundle)
	}
	return err
}

func (b *Bundle) SetForceRebootstrap() error {
	//FIXME KMF add retry counter to StoreBootstrapState too?
	b.use = UseRebootstrap
	err := b.storage.StoreBootstrapState(b.use, b.startTime)
	if err != nil {
		return err
	}
	err = b.storage.DeleteSVID()
	if err != nil {
		return err
	}
	err = b.storage.StoreBundle(nil)
	return err
}

func (b *Bundle) GetStartTime() (time.Time, error) {
	var err error
	if b.startTime.IsZero() {
		b.startTime = time.Now()
		err = b.storage.StoreBootstrapState(b.use, b.startTime)
	}
	return b.startTime, err
}

func (b *Bundle) IsBootstrap() bool {
	return b.use != UseRebootstrap
}

func (b *Bundle) IsRebootstrap() bool {
	return b.use == UseRebootstrap
}

func (b *Bundle) GetBundle() ([]*x509.Certificate, error) {
	var bundleBytes []byte
	var err error

	b.connectionAttempts++
	if b.startTime.IsZero() {
		b.startTime = time.Now()
		err = b.storage.StoreBootstrapState(b.use, b.startTime)
		if err == nil {
			return nil, err
		}
	}

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

	b.lastBundle = bundle

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
