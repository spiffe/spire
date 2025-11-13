package trustbundlesources

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/storage"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

type Bundle struct {
	config             *Config
	use                int
	connectionAttempts int
	startTime          time.Time
	log                logrus.FieldLogger
	metrics            telemetry.Metrics
	storage            storage.Storage
	lastBundle         []*x509.Certificate
}

func New(config *Config, log logrus.FieldLogger) Bundle {
	return Bundle{
		config: config,
		log:    log,
	}
}

func (b *Bundle) SetMetrics(metrics telemetry.Metrics) {
	b.metrics = metrics
}

func (b *Bundle) SetStorage(sto storage.Storage) error {
	b.storage = sto
	use, startTime, connectionAttempts, err := b.storage.LoadBootstrapState()
	b.use = use
	b.startTime = startTime
	b.connectionAttempts = connectionAttempts
	if use == UseUnspecified {
		b.use = UseBootstrap
		BootstrapTrustBundle, err := b.storage.LoadBundle()
		if err != nil {
			if !errors.Is(err, storage.ErrNotCached) {
				return err
			}
			b.use = UseBootstrap
		} else if len(BootstrapTrustBundle) > 0 {
			b.use = UseRebootstrap
		}
	}
	b.updateMetrics()
	return err
}

func (b *Bundle) SetUse(use int) error {
	if b.use != use {
		b.use = use
		b.connectionAttempts = 0
		b.startTime = time.Now()
		b.log.Info("Setting use.")
		err := b.storage.StoreBootstrapState(use, b.startTime, b.connectionAttempts)
		if err != nil {
			return err
		}
		b.updateMetrics()
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
	b.log.Info(fmt.Sprintf("Success after %s attempts=%d", time.Since(b.startTime), b.connectionAttempts))
	b.use = UseRebootstrap
	b.connectionAttempts = 0
	b.startTime = time.Time{}
	b.log.Info("Setting use.")
	if b.storage != nil {
		if err := b.storage.StoreBootstrapState(b.use, b.startTime, b.connectionAttempts); err != nil {
			return err
		}
		b.updateMetrics()
		return b.storage.StoreBundle(b.lastBundle)
	}
	return nil
}

func (b *Bundle) SetForceRebootstrap() error {
	b.use = UseRebootstrap
	b.startTime = time.Now()
	b.connectionAttempts = 0
	err := b.storage.StoreBootstrapState(b.use, b.startTime, b.connectionAttempts)
	if err != nil {
		return err
	}
	b.updateMetrics()
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
		err = b.storage.StoreBootstrapState(b.use, b.startTime, b.connectionAttempts)
		b.updateMetrics()
	}
	return b.startTime, err
}

func (b *Bundle) IsBootstrap() bool {
	return b.use != UseRebootstrap
}

func (b *Bundle) IsRebootstrap() bool {
	return b.use == UseRebootstrap
}

func (b *Bundle) GetBundle() ([]*x509.Certificate, bool, error) {
	var bundleBytes []byte
	var err error

	b.connectionAttempts++
	if b.startTime.IsZero() {
		b.startTime = time.Now()
	}
	err = b.storage.StoreBootstrapState(b.use, b.startTime, b.connectionAttempts)
	if err != nil {
		return nil, false, err
	}
	b.updateMetrics()

	switch {
	case b.config.TrustBundleURL != "":
		u, err := url.Parse(b.config.TrustBundleURL)
		if err != nil {
			return nil, false, fmt.Errorf("unable to parse trust bundle URL: %w", err)
		}
		if b.config.TrustBundleUnixSocket != "" {
			params := u.Query()
			if b.use == UseRebootstrap {
				params.Set("spire-attest-mode", "rebootstrap")
			} else {
				params.Set("spire-attest-mode", "bootstrap")
			}
			params.Set("spire-connection-attempts", strconv.Itoa(b.connectionAttempts))
			params.Set("spire-attest-start-time", b.startTime.Format(time.RFC3339))
			params.Set("spire-server-address", b.config.ServerAddress)
			params.Set("spire-server-port", strconv.Itoa(b.config.ServerPort))
			params.Set("spiffe-trust-domain", b.config.TrustDomain)
			u.RawQuery = params.Encode()
		}
		if b.use == UseRebootstrap {
			b.log.Info(fmt.Sprintf("Server reattestation attempt %d. Started %s.", b.connectionAttempts, b.startTime.Format(time.RFC3339)))
		} else {
			b.log.Info(fmt.Sprintf("Server attestation attempt %d. Started %s.", b.connectionAttempts, b.startTime.Format(time.RFC3339)))
		}
		b.log.Debug(fmt.Sprintf("Server attestation url: %s from: ", u.String()), b.config.TrustBundleUnixSocket)
		bundleBytes, err = downloadTrustBundle(u.String(), b.config.TrustBundleUnixSocket)
		if err != nil {
			return nil, false, err
		}
	case b.config.TrustBundlePath != "":
		bundleBytes, err = loadTrustBundle(b.config.TrustBundlePath)
		if err != nil {
			return nil, false, fmt.Errorf("could not parse trust bundle: %w", err)
		}
	default:
		// If InsecureBootstrap is configured, the bundle is not required
		if b.config.InsecureBootstrap {
			return nil, true, nil
		}
	}

	bundle, err := parseTrustBundle(bundleBytes, b.config.TrustBundleFormat)
	if err != nil {
		return nil, false, err
	}

	if len(bundle) == 0 {
		return nil, false, errors.New("no certificates found in trust bundle")
	}

	b.lastBundle = bundle

	return bundle, false, nil
}

func (b *Bundle) GetInsecureBootstrap() bool {
	return b.config.InsecureBootstrap
}

func (b *Bundle) updateMetrics() {
	seconds := b.startTime.Unix()
	use := "rebootstrap"
	if b.use != UseRebootstrap {
		use = "bootstrap"
	}
	bootstrapped := 0
	if b.startTime.IsZero() {
		bootstrapped = 1
	}
	b.metrics.SetGaugeWithLabels([]string{"bootstraped"}, float32(bootstrapped), []telemetry.Label{})
	b.metrics.SetGaugeWithLabels([]string{"bootstrap_seconds"}, float32(seconds), []telemetry.Label{
		{Name: "mode", Value: use},
	})
	b.metrics.SetGaugeWithLabels([]string{"bootstrap_attempts"}, float32(b.connectionAttempts), []telemetry.Label{
		{Name: "mode", Value: use},
	})
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
