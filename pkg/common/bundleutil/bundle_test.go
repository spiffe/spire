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

func TestBundleUtilTestSuite(t *testing.T) {
	spiretest.Run(t, new(BundleUtilTestSuite))
}

type BundleUtilTestSuite struct {
	spiretest.Suite
	currentTime      int64
	certNotExpired   *x509.Certificate
	certExpired      *x509.Certificate
	jwtKeyExpired    *common.PublicKey
	jwtKeyNotExpired *common.PublicKey
}

func (s *BundleUtilTestSuite) SetupTest() {
	// currentTime is a point in time between expired and not-expired certs and keys
	parsedTime, err := time.Parse(time.RFC3339, "2018-02-10T01:35:00+00:00")
	s.Require().NoError(err)
	s.currentTime = parsedTime.Unix()

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

func (s *BundleUtilTestSuite) TestPruneBundleFailIfNilBundle() {
	newBundle, err := PruneBundle(nil, 0, hclog.NewNullLogger())
	s.AssertErrorContains(err, "current bundle is nil")
	s.Nil(newBundle)
}

func (s *BundleUtilTestSuite) TestPruneBundleFailIfTimeIsZero() {
	bundle := s.createBundle(
		[]*x509.Certificate{s.certNotExpired, s.certExpired},
		[]*common.PublicKey{s.jwtKeyNotExpired, s.jwtKeyExpired},
	)

	newBundle, err := PruneBundle(bundle, 0, hclog.NewNullLogger())
	s.AssertErrorContains(err, "expiration time is 0")
	s.Nil(newBundle)
}

func (s *BundleUtilTestSuite) TestPruneBundleFailIfAllCertExpired() {
	bundle := s.createBundle(
		[]*x509.Certificate{s.certExpired},
		[]*common.PublicKey{s.jwtKeyNotExpired, s.jwtKeyExpired},
	)

	newBundle, err := PruneBundle(bundle, s.currentTime, hclog.NewNullLogger())
	s.AssertErrorContains(err, "would prune all certificates")
	s.Nil(newBundle)
}

func (s *BundleUtilTestSuite) TestPruneBundleFailIfAllJWTExpired() {
	bundle := s.createBundle(
		[]*x509.Certificate{s.certNotExpired, s.certExpired},
		[]*common.PublicKey{s.jwtKeyExpired},
	)

	newBundle, err := PruneBundle(bundle, s.currentTime, hclog.NewNullLogger())
	s.AssertErrorContains(err, "would prune all JWT signing keys")
	s.Nil(newBundle)
}

func (s *BundleUtilTestSuite) TestPruneBundleSucceeds() {
	bundle := s.createBundle(
		[]*x509.Certificate{s.certNotExpired, s.certExpired},
		[]*common.PublicKey{s.jwtKeyNotExpired, s.jwtKeyExpired},
	)

	expectedBundle := s.createBundle(
		[]*x509.Certificate{s.certNotExpired},
		[]*common.PublicKey{s.jwtKeyNotExpired},
	)

	newBundle, err := PruneBundle(bundle, s.currentTime, hclog.NewNullLogger())
	s.NoError(err)
	s.Equal(expectedBundle, newBundle)
}

func (s *BundleUtilTestSuite) createBundle(certs []*x509.Certificate, jwtKeys []*common.PublicKey) *common.Bundle {
	bundle := BundleProtoFromRootCAs("spiffe://foo", certs)
	bundle.JwtSigningKeys = jwtKeys
	return bundle
}
