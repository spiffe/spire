package manager

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/golang/protobuf/proto"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/proto/common"
	"github.com/zeebo/errs"
)

// ReadBundle returns the bundle located at bundleCachePath. Returns nil
// if there was some reason by which the bundle couldn't be loaded along with
// the error reason.
func ReadBundle(path string) (*bundleutil.Bundle, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotCached
		}
		return nil, errs.New("error reading bundle at %s: %v", path, err)
	}

	if len(data) == 0 {
		return nil, ErrNotCached
	}

	bundle, err := bundleutil.ParseBundle(data)
	if err != nil {
		return nil, errs.New("error parsing bundle at %s: %v", path, err)
	}
	return bundle, nil
}

func MigrateBundle(trustDomainID string, oldPath, newPath string) error {
	data, err := ioutil.ReadFile(oldPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return errs.New("error reading bundle at %s: %v", oldPath, err)
	}

	bundle, err := bundleutil.BundleProtoFromRootCAsDER(trustDomainID, data)
	if err != nil {
		return errs.New("error parsing bundle at %s: %v", oldPath, err)
	}

	if err := StoreBundleProto(newPath, bundle); err != nil {
		return err
	}

	if err := os.Remove(oldPath); err != nil {
		return errs.New("unable to remove old bundle: %v", err)
	}

	return nil
}

// StoreBundle writes the bundle to disk into bundleCachePath. Returns nil if all went
// fine, otherwise ir returns an error.
func StoreBundle(path string, bundle *bundleutil.Bundle) error {
	if bundle == nil {
		if err := diskutil.AtomicWriteFile(path, []byte{}, 0644); err != nil {
			return errs.New("unable to write bundle to %s: %v", path, err)
		}
		return nil
	}
	return StoreBundleProto(path, bundle.Proto())
}

func StoreBundleProto(path string, bundle *common.Bundle) error {
	bundleBytes, err := proto.Marshal(bundle)
	if err != nil {
		return errs.New("unable to marshal bundle: %v", err)
	}

	if err := diskutil.AtomicWriteFile(path, bundleBytes, 0644); err != nil {
		return errs.New("unable to write bundle to %s: %v", path, err)
	}

	return nil
}

// ReadSVID returns the SVID located at svidCachePath. Returns nil
// if there was some reason by which the SVID couldn't be loaded along
// with the error reason.
func ReadSVID(svidCachePath string) ([]*x509.Certificate, error) {
	data, err := ioutil.ReadFile(svidCachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotCached
		}
		return nil, fmt.Errorf("error reading SVID at %s: %s", svidCachePath, err)
	}

	certChain, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("error parsing SVID at %s: %s", svidCachePath, err)
	}
	return certChain, nil
}

// StoreSVID writes the specified svid to disk into svidCachePath. Returns nil if all went
// fine, otherwise ir returns an error.
func StoreSVID(svidCachePath string, svidChain []*x509.Certificate) error {
	data := &bytes.Buffer{}
	for _, cert := range svidChain {
		data.Write(cert.Raw)
	}
	return diskutil.AtomicWriteFile(svidCachePath, data.Bytes(), 0600)
}
