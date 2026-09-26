package sigstore

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

	// sigstoreRootFileEnv locates an alternate TUF root trust anchor file.
	sigstoreRootFileEnv = "SIGSTORE_ROOT_FILE"

	remoteCacheFile = "remote.json"
	tufRootFile     = "root.json"
)

type remoteCache struct {
	Mirror string `json:"mirror"`
}

var (
	fulcioPoolsMu       sync.Mutex
	fulcioRoots         *x509.CertPool
	fulcioIntermediates *x509.CertPool
	fetchFulcioCAs      = defaultFetchFulcioCertificateAuthorities
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
	fulcioPoolsMu.Lock()
	defer fulcioPoolsMu.Unlock()

	if fulcioRoots != nil {
		return fulcioRoots, fulcioIntermediates, nil
	}

	opts, err := tufOptions()
	if err != nil {
		return nil, nil, err
	}

	cas, err := fetchFulcioCAs(opts)
	if err != nil {
		return nil, nil, err
	}

	roots, intermediates, err := certPoolsFromCertificateAuthorities(cas)
	if err != nil {
		return nil, nil, err
	}

	fulcioRoots = roots
	fulcioIntermediates = intermediates
	return fulcioRoots, fulcioIntermediates, nil
}

func defaultFetchFulcioCertificateAuthorities(opts *tuf.Options) ([]sigstoreroot.CertificateAuthority, error) {
	trustedRoot, err := sigstoreroot.FetchTrustedRootWithOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch sigstore trusted root: %w", err)
	}
	return trustedRoot.FulcioCertificateAuthorities(), nil
}

func certPoolsFromCertificateAuthorities(cas []sigstoreroot.CertificateAuthority) (*x509.CertPool, *x509.CertPool, error) {
	if len(cas) == 0 {
		return nil, nil, errors.New("no fulcio certificate authorities found in trusted root")
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	for _, ca := range cas {
		fulcioCA, ok := ca.(*sigstoreroot.FulcioCertificateAuthority)
		if !ok {
			return nil, nil, fmt.Errorf("unexpected certificate authority type: %T", ca)
		}
		if fulcioCA.Root == nil {
			return nil, nil, errors.New("fulcio certificate authority missing root certificate")
		}
		roots.AddCert(fulcioCA.Root)
		for _, cert := range fulcioCA.Intermediates {
			intermediates.AddCert(cert)
		}
	}

	return roots, intermediates, nil
}

func tufCacheRoot() string {
	if rootDir := os.Getenv(tufRootEnv); rootDir != "" {
		return rootDir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), ".sigstore", "root")
	}
	return filepath.Join(home, ".sigstore", "root")
}

func readRemoteMirror(cacheRoot string) (string, error) {
	path := filepath.Join(cacheRoot, remoteCacheFile)
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("reading %s: %w", remoteCacheFile, err)
	}

	var remote remoteCache
	if err := json.Unmarshal(b, &remote); err != nil {
		return "", fmt.Errorf("parsing %s: %w", remoteCacheFile, err)
	}
	return remote.Mirror, nil
}

func loadTUFRootBytes(cacheRoot string) ([]byte, error) {
	if path := os.Getenv(sigstoreRootFileEnv); path != "" {
		// #nosec G703 -- operator-provided trust root path via SIGSTORE_ROOT_FILE
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", sigstoreRootFileEnv, err)
		}
		return b, nil
	}

	path := filepath.Join(cacheRoot, tufRootFile)
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", tufRootFile, err)
	}
	return b, nil
}

// tufOptions returns TUF client options honoring TUF_ROOT, SIGSTORE_NO_CACHE, and
// remote.json (written by cosign initialize), matching the deprecated
// sigstore/pkg/tuf.NewFromEnv mirror selection behavior.
func tufOptions() (*tuf.Options, error) {
	opts := tuf.DefaultOptions()
	opts.CachePath = tufCacheRoot()

	if noCache, err := strconv.ParseBool(os.Getenv(sigstoreNoCacheEnv)); err == nil {
		opts.DisableLocalCache = noCache
	}

	mirror, err := readRemoteMirror(opts.CachePath)
	if err != nil {
		return nil, err
	}
	if mirror != "" {
		opts.RepositoryBaseURL = mirror
	}

	if opts.RepositoryBaseURL != tuf.DefaultMirror {
		root, err := loadTUFRootBytes(opts.CachePath)
		if err != nil {
			return nil, err
		}
		if root != nil {
			opts.Root = root
		}
	}

	return opts, nil
}
