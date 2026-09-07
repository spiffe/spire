package sigstore

import (
	"crypto/x509"
	"fmt"
	"os"
	"strconv"
	"sync"

	sigstoreroot "github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

const (
	// tufRootEnv locates an alternate local TUF root location.
	tufRootEnv = "TUF_ROOT"

	// sigstoreNoCacheEnv, when set, keeps TUF root data in memory only.
	sigstoreNoCacheEnv = "SIGSTORE_NO_CACHE"
)

var (
	fulcioPoolsOnce     sync.Once
	fulcioRoots         *x509.CertPool
	fulcioIntermediates *x509.CertPool
	fulcioPoolsErr      error
)

func getFulcioRoots() (*x509.CertPool, error) {
	roots, _, err := loadFulcioCertPools()
	return roots, err
}

func getFulcioIntermediates() (*x509.CertPool, error) {
	_, intermediates, err := loadFulcioCertPools()
	return intermediates, err
}

func loadFulcioCertPools() (*x509.CertPool, *x509.CertPool, error) {
	fulcioPoolsOnce.Do(func() {
		trustedRoot, err := sigstoreroot.FetchTrustedRootWithOptions(tufOptions())
		if err != nil {
			fulcioPoolsErr = fmt.Errorf("failed to fetch sigstore trusted root: %w", err)
			return
		}
		fulcioRoots, fulcioIntermediates, fulcioPoolsErr = certPoolsFromCertificateAuthorities(trustedRoot.FulcioCertificateAuthorities())
	})
	return fulcioRoots, fulcioIntermediates, fulcioPoolsErr
}

func certPoolsFromCertificateAuthorities(cas []sigstoreroot.CertificateAuthority) (*x509.CertPool, *x509.CertPool, error) {
	if len(cas) == 0 {
		return nil, nil, fmt.Errorf("no fulcio certificate authorities found in trusted root")
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	for _, ca := range cas {
		fulcioCA, ok := ca.(*sigstoreroot.FulcioCertificateAuthority)
		if !ok {
			return nil, nil, fmt.Errorf("unexpected certificate authority type: %T", ca)
		}
		if fulcioCA.Root == nil {
			return nil, nil, fmt.Errorf("fulcio certificate authority missing root certificate")
		}
		roots.AddCert(fulcioCA.Root)
		for _, cert := range fulcioCA.Intermediates {
			intermediates.AddCert(cert)
		}
	}

	return roots, intermediates, nil
}

// tufOptions returns TUF client options honoring TUF_ROOT and SIGSTORE_NO_CACHE,
// matching the behavior of the deprecated sigstore/pkg/tuf.NewFromEnv path.
func tufOptions() *tuf.Options {
	opts := tuf.DefaultOptions()
	if rootDir := os.Getenv(tufRootEnv); rootDir != "" {
		opts.CachePath = rootDir
	}
	if noCache, err := strconv.ParseBool(os.Getenv(sigstoreNoCacheEnv)); err == nil {
		opts.DisableLocalCache = noCache
	}
	return opts
}
