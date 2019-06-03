package bundleutil

// Basic imports
import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"

	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
)

func TestBundleUtilSuite(t *testing.T) {
	spiretest.Run(t, new(BundleUtilSuite))
}

type BundleUtilSuite struct {
	spiretest.Suite
	currentTime      time.Time
	certNotExpired   *x509.Certificate
	certExpired      *x509.Certificate
	jwtKeyExpired    *common.PublicKey
	jwtKeyNotExpired *common.PublicKey
}

func (s *BundleUtilSuite) SetupTest() {
	// currentTime is a point in time between expired and not-expired certs and keys
	var err error
	s.currentTime, err = time.Parse(time.RFC3339, "2018-02-10T01:35:00+00:00")
	s.Require().NoError(err)

	s.certNotExpired, _, err = util.LoadSVIDFixture()
	s.Require().NoError(err)

	s.certExpired, _, err = util.LoadCAFixture()
	s.Require().NoError(err)

	expiredKeyTime, err := time.Parse(time.RFC3339, "2018-01-10T01:35:00+00:00")
	s.Require().NoError(err)
	s.jwtKeyExpired = &common.PublicKey{NotAfter: expiredKeyTime.Unix()}

	nonExpiredKeyTime, err := time.Parse(time.RFC3339, "2018-03-10T01:35:00+00:00")
	s.Require().NoError(err)
	s.jwtKeyNotExpired = &common.PublicKey{NotAfter: nonExpiredKeyTime.Unix()}
}

func (s *BundleUtilSuite) TestPruneBundleFailIfNilBundle() {
	newBundle, changed, err := PruneBundle(nil, time.Now(), hclog.NewNullLogger())
	s.AssertErrorContains(err, "current bundle is nil")
	s.Nil(newBundle)
	s.False(changed)
}

func (s *BundleUtilSuite) TestPruneBundleFailIfTimeIsZero() {
	bundle := s.createBundle(
		[]*x509.Certificate{s.certNotExpired, s.certExpired},
		[]*common.PublicKey{s.jwtKeyNotExpired, s.jwtKeyExpired},
	)

	newBundle, changed, err := PruneBundle(bundle, time.Time{}, hclog.NewNullLogger())
	s.AssertErrorContains(err, "expiration time is zero value")
	s.Nil(newBundle)
	s.False(changed)
}

func (s *BundleUtilSuite) TestPruneBundleFailIfAllCertExpired() {
	bundle := s.createBundle(
		[]*x509.Certificate{s.certExpired},
		[]*common.PublicKey{s.jwtKeyNotExpired, s.jwtKeyExpired},
	)

	newBundle, changed, err := PruneBundle(bundle, s.currentTime, hclog.NewNullLogger())
	s.AssertErrorContains(err, "would prune all certificates")
	s.Nil(newBundle)
	s.False(changed)
}

func (s *BundleUtilSuite) TestPruneBundleFailIfAllJWTExpired() {
	bundle := s.createBundle(
		[]*x509.Certificate{s.certNotExpired, s.certExpired},
		[]*common.PublicKey{s.jwtKeyExpired},
	)

	newBundle, changed, err := PruneBundle(bundle, s.currentTime, hclog.NewNullLogger())
	s.AssertErrorContains(err, "would prune all JWT signing keys")
	s.Nil(newBundle)
	s.False(changed)
}

func (s *BundleUtilSuite) TestPruneBundleSucceeds() {
	bundle := s.createBundle(
		[]*x509.Certificate{s.certNotExpired, s.certExpired},
		[]*common.PublicKey{s.jwtKeyNotExpired, s.jwtKeyExpired},
	)

	expectedBundle := s.createBundle(
		[]*x509.Certificate{s.certNotExpired},
		[]*common.PublicKey{s.jwtKeyNotExpired},
	)

	newBundle, changed, err := PruneBundle(bundle, s.currentTime, hclog.NewNullLogger())
	s.NoError(err)
	s.Equal(expectedBundle, newBundle)
	s.True(changed)
}

func (s *BundleUtilSuite) createBundle(certs []*x509.Certificate, jwtKeys []*common.PublicKey) *common.Bundle {
	bundle := BundleProtoFromRootCAs("spiffe://foo", certs)
	bundle.JwtSigningKeys = jwtKeys
	return bundle
}
