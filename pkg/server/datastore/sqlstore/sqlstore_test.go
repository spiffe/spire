package sqlstore

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/protoutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	testutil "github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

var (
	ctx = context.Background()

	// The following are set by the linker during integration tests to
	// run these unit tests against various SQL backends.
	TestDialect      string
	TestConnString   string
	TestROConnString string
	// Replication to replica can take some time,
	// if specified, this configuration setting tells the duration to wait before running queries in read-only databases
	TestReadOnlyDelay string
)

const (
	_ttl                   = time.Hour
	_expiredNotAfterString = "2018-01-10T01:34:00+00:00"
	_validNotAfterString   = "2018-01-10T01:36:00+00:00"
	_middleTimeString      = "2018-01-10T01:35:00+00:00"
	_notFoundErrMsg        = "datastore-sql: record not found"
)

func TestPlugin(t *testing.T) {
	spiretest.Run(t, new(PluginSuite))
}

type PluginSuite struct {
	spiretest.Suite

	cert   *x509.Certificate
	cacert *x509.Certificate

	dir    string
	nextID int
	ds     *Plugin
	hook   *test.Hook

	readOnlyDelay time.Duration
}

func (s *PluginSuite) SetupSuite() {
	clk := clock.NewMock(s.T())

	expiredNotAfterTime, err := time.Parse(time.RFC3339, _expiredNotAfterString)
	s.Require().NoError(err)
	validNotAfterTime, err := time.Parse(time.RFC3339, _validNotAfterString)
	s.Require().NoError(err)

	caTemplate, err := testutil.NewCATemplate(clk, spiffeid.RequireTrustDomainFromString("foo"))
	s.Require().NoError(err)

	caTemplate.NotAfter = expiredNotAfterTime
	caTemplate.NotBefore = expiredNotAfterTime.Add(-_ttl)

	cacert, cakey, err := testutil.SelfSign(caTemplate)
	s.Require().NoError(err)

	svidTemplate, err := testutil.NewSVIDTemplate(clk, "spiffe://foo/id1")
	s.Require().NoError(err)

	svidTemplate.NotAfter = validNotAfterTime
	svidTemplate.NotBefore = validNotAfterTime.Add(-_ttl)

	cert, _, err := testutil.Sign(svidTemplate, cacert, cakey)
	s.Require().NoError(err)

	s.cacert = cacert
	s.cert = cert

	if TestReadOnlyDelay != "" {
		delay, err := time.ParseDuration(TestReadOnlyDelay)
		s.Require().NoError(err, "failed to parse read-only delay")
		s.readOnlyDelay = delay
	}
}

func (s *PluginSuite) SetupTest() {
	s.dir = s.TempDir()
	s.ds = s.newPlugin()
}

func (s *PluginSuite) TearDownTest() {
	if s.ds != nil {
		s.ds.Close()
	}
}

func (s *PluginSuite) newPlugin() *Plugin {
	log, hook := test.NewNullLogger()
	ds := New(log)
	s.hook = hook

	// When the test suite is executed normally, we test against sqlite3 since
	// it requires no external dependencies. The integration test framework
	// builds the test harness for a specific dialect and connection string
	switch TestDialect {
	case "":
		s.nextID++
		dbPath := filepath.ToSlash(filepath.Join(s.dir, fmt.Sprintf("db%d.sqlite3", s.nextID)))
		err := ds.Configure(ctx, fmt.Sprintf(`
			database_type = "sqlite3"
			log_sql = true
			connection_string = "%s"
		`, dbPath))
		s.Require().NoError(err)

		// assert that WAL journal mode is enabled
		jm := struct {
			JournalMode string
		}{}
		ds.db.Raw("PRAGMA journal_mode").Scan(&jm)
		s.Require().Equal(jm.JournalMode, "wal")

		// assert that foreign_key support is enabled
		fk := struct {
			ForeignKeys string
		}{}
		ds.db.Raw("PRAGMA foreign_keys").Scan(&fk)
		s.Require().Equal(fk.ForeignKeys, "1")
	case "mysql":
		s.T().Logf("CONN STRING: %q", TestConnString)
		s.Require().NotEmpty(TestConnString, "connection string must be set")
		wipeMySQL(s.T(), TestConnString)
		err := ds.Configure(ctx, fmt.Sprintf(`
			database_type = "mysql"
			log_sql = true
			connection_string = "%s"
			ro_connection_string = "%s"
		`, TestConnString, TestROConnString))
		s.Require().NoError(err)
	case "postgres":
		s.T().Logf("CONN STRING: %q", TestConnString)
		s.Require().NotEmpty(TestConnString, "connection string must be set")
		wipePostgres(s.T(), TestConnString)
		err := ds.Configure(ctx, fmt.Sprintf(`
			database_type = "postgres"
			log_sql = true
			connection_string = "%s"
			ro_connection_string = "%s"
		`, TestConnString, TestROConnString))
		s.Require().NoError(err)
	default:
		s.Require().FailNowf("Unsupported external test dialect %q", TestDialect)
	}

	return ds
}

func (s *PluginSuite) TestInvalidPluginConfiguration() {
	err := s.ds.Configure(ctx, `
		database_type = "wrong"
		connection_string = "bad"
	`)
	s.RequireErrorContains(err, "datastore-sql: unsupported database_type: wrong")
}

func (s *PluginSuite) TestInvalidMySQLConfiguration() {
	err := s.ds.Configure(ctx, `
		database_type = "mysql"
		connection_string = "username:@tcp(127.0.0.1)/spire_test"
	`)
	s.RequireErrorContains(err, "datastore-sql: invalid mysql config: missing parseTime=true param in connection_string")

	err = s.ds.Configure(ctx, `
		database_type = "mysql"
		ro_connection_string = "username:@tcp(127.0.0.1)/spire_test"
	`)
	s.RequireErrorContains(err, "datastore-sql: connection_string must be set")

	err = s.ds.Configure(ctx, `
		database_type = "mysql"
	`)
	s.RequireErrorContains(err, "datastore-sql: connection_string must be set")
}

func (s *PluginSuite) TestBundleCRUD() {
	bundle := bundleutil.BundleProtoFromRootCA("spiffe://foo", s.cert)

	// fetch non-existent
	fb, err := s.ds.FetchBundle(ctx, "spiffe://foo")
	s.Require().NoError(err)
	s.Require().Nil(fb)

	// update non-existent
	_, err = s.ds.UpdateBundle(ctx, bundle, nil)
	s.RequireGRPCStatus(err, codes.NotFound, _notFoundErrMsg)

	// delete non-existent
	err = s.ds.DeleteBundle(ctx, "spiffe://foo", datastore.Restrict)
	s.RequireGRPCStatus(err, codes.NotFound, _notFoundErrMsg)

	// create
	_, err = s.ds.CreateBundle(ctx, bundle)
	s.Require().NoError(err)

	// create again (constraint violation)
	_, err = s.ds.CreateBundle(ctx, bundle)
	s.Equal(status.Code(err), codes.AlreadyExists)

	// fetch
	fb, err = s.ds.FetchBundle(ctx, "spiffe://foo")
	s.Require().NoError(err)
	s.AssertProtoEqual(bundle, fb)

	// list
	lresp, err := s.ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	s.Require().NoError(err)
	s.Equal(1, len(lresp.Bundles))
	s.AssertProtoEqual(bundle, lresp.Bundles[0])

	bundle2 := bundleutil.BundleProtoFromRootCA(bundle.TrustDomainId, s.cacert)
	appendedBundle := bundleutil.BundleProtoFromRootCAs(bundle.TrustDomainId,
		[]*x509.Certificate{s.cert, s.cacert})
	appendedBundle.SequenceNumber++

	// append
	ab, err := s.ds.AppendBundle(ctx, bundle2)
	s.Require().NoError(err)
	s.Require().NotNil(ab)
	s.AssertProtoEqual(appendedBundle, ab)
	// stored bundle was updated
	bundle.SequenceNumber = appendedBundle.SequenceNumber

	// append identical
	ab, err = s.ds.AppendBundle(ctx, bundle2)
	s.Require().NoError(err)
	s.Require().NotNil(ab)
	s.AssertProtoEqual(appendedBundle, ab)

	// append on a new bundle
	bundle3 := bundleutil.BundleProtoFromRootCA("spiffe://bar", s.cacert)
	ab, err = s.ds.AppendBundle(ctx, bundle3)
	s.Require().NoError(err)
	s.AssertProtoEqual(bundle3, ab)

	// update with mask: RootCas
	updatedBundle, err := s.ds.UpdateBundle(ctx, bundle, &common.BundleMask{
		RootCas: true,
	})
	s.Require().NoError(err)
	s.AssertProtoEqual(bundle, updatedBundle)

	lresp, err = s.ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	s.Require().NoError(err)
	assertBundlesEqual(s.T(), []*common.Bundle{bundle, bundle3}, lresp.Bundles)

	// update with mask: RefreshHint
	bundle.RefreshHint = 60
	updatedBundle, err = s.ds.UpdateBundle(ctx, bundle, &common.BundleMask{
		RefreshHint: true,
	})
	s.Require().NoError(err)
	s.AssertProtoEqual(bundle, updatedBundle)

	// update with mask: SequenceNumber
	bundle.SequenceNumber = 100
	updatedBundle, err = s.ds.UpdateBundle(ctx, bundle, &common.BundleMask{
		SequenceNumber: true,
	})
	s.Require().NoError(err)
	s.AssertProtoEqual(bundle, updatedBundle)
	assert.Equal(s.T(), bundle.SequenceNumber, updatedBundle.SequenceNumber)

	lresp, err = s.ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	s.Require().NoError(err)
	assertBundlesEqual(s.T(), []*common.Bundle{bundle, bundle3}, lresp.Bundles)

	// update with mask: JwtSingingKeys
	bundle.JwtSigningKeys = []*common.PublicKey{{Kid: "jwt-key-1"}}
	updatedBundle, err = s.ds.UpdateBundle(ctx, bundle, &common.BundleMask{
		JwtSigningKeys: true,
	})
	s.Require().NoError(err)
	s.AssertProtoEqual(bundle, updatedBundle)

	lresp, err = s.ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	s.Require().NoError(err)
	assertBundlesEqual(s.T(), []*common.Bundle{bundle, bundle3}, lresp.Bundles)

	// update without mask
	updatedBundle, err = s.ds.UpdateBundle(ctx, bundle2, nil)
	s.Require().NoError(err)
	s.AssertProtoEqual(bundle2, updatedBundle)

	lresp, err = s.ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	s.Require().NoError(err)
	assertBundlesEqual(s.T(), []*common.Bundle{bundle2, bundle3}, lresp.Bundles)

	// delete
	err = s.ds.DeleteBundle(ctx, bundle.TrustDomainId, datastore.Restrict)
	s.Require().NoError(err)

	lresp, err = s.ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	s.Require().NoError(err)
	s.Equal(1, len(lresp.Bundles))
	s.AssertProtoEqual(bundle3, lresp.Bundles[0])
}

func (s *PluginSuite) TestListBundlesWithPagination() {
	bundle1 := bundleutil.BundleProtoFromRootCA("spiffe://example.org", s.cert)
	_, err := s.ds.CreateBundle(ctx, bundle1)
	s.Require().NoError(err)

	bundle2 := bundleutil.BundleProtoFromRootCA("spiffe://foo", s.cacert)
	_, err = s.ds.CreateBundle(ctx, bundle2)
	s.Require().NoError(err)

	bundle3 := bundleutil.BundleProtoFromRootCA("spiffe://bar", s.cert)
	_, err = s.ds.CreateBundle(ctx, bundle3)
	s.Require().NoError(err)

	bundle4 := bundleutil.BundleProtoFromRootCA("spiffe://baz", s.cert)
	_, err = s.ds.CreateBundle(ctx, bundle4)
	s.Require().NoError(err)

	tests := []struct {
		name               string
		pagination         *datastore.Pagination
		expectedList       []*common.Bundle
		expectedPagination *datastore.Pagination
		expectedErr        string
	}{
		{
			name:         "no pagination",
			expectedList: []*common.Bundle{bundle1, bundle2, bundle3, bundle4},
		},
		{
			name: "page size bigger than items",
			pagination: &datastore.Pagination{
				PageSize: 5,
			},
			expectedList: []*common.Bundle{bundle1, bundle2, bundle3, bundle4},
			expectedPagination: &datastore.Pagination{
				Token:    "4",
				PageSize: 5,
			},
		},
		{
			name: "pagination page size is zero",
			pagination: &datastore.Pagination{
				PageSize: 0,
			},
			expectedErr: "rpc error: code = InvalidArgument desc = cannot paginate with pagesize = 0",
		},
		{
			name: "bundles first page",
			pagination: &datastore.Pagination{
				Token:    "0",
				PageSize: 2,
			},
			expectedList: []*common.Bundle{bundle1, bundle2},
			expectedPagination: &datastore.Pagination{Token: "2",
				PageSize: 2,
			},
		},
		{
			name: "bundles second page",
			pagination: &datastore.Pagination{
				Token:    "2",
				PageSize: 2,
			},
			expectedList: []*common.Bundle{bundle3, bundle4},
			expectedPagination: &datastore.Pagination{
				Token:    "4",
				PageSize: 2,
			},
		},
		{
			name:         "bundles third page",
			expectedList: []*common.Bundle{},
			pagination: &datastore.Pagination{
				Token:    "4",
				PageSize: 2,
			},
			expectedPagination: &datastore.Pagination{
				Token:    "",
				PageSize: 2,
			},
		},
		{
			name:         "invalid token",
			expectedList: []*common.Bundle{},
			expectedErr:  "rpc error: code = InvalidArgument desc = could not parse token 'invalid token'",
			pagination: &datastore.Pagination{
				Token:    "invalid token",
				PageSize: 2,
			},
			expectedPagination: &datastore.Pagination{
				PageSize: 2,
			},
		},
	}
	for _, test := range tests {
		test := test
		s.T().Run(test.name, func(t *testing.T) {
			resp, err := s.ds.ListBundles(ctx, &datastore.ListBundlesRequest{
				Pagination: test.pagination,
			})
			if test.expectedErr != "" {
				require.EqualError(t, err, test.expectedErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)

			spiretest.RequireProtoListEqual(t, test.expectedList, resp.Bundles)
			require.Equal(t, test.expectedPagination, resp.Pagination)
		})
	}
}

func (s *PluginSuite) TestCountBundles() {
	// Count empty bundles
	count, err := s.ds.CountBundles(ctx)
	s.Require().NoError(err)
	s.Require().Equal(int32(0), count)

	// Create bundles
	bundle1 := bundleutil.BundleProtoFromRootCA("spiffe://example.org", s.cert)
	_, err = s.ds.CreateBundle(ctx, bundle1)
	s.Require().NoError(err)

	bundle2 := bundleutil.BundleProtoFromRootCA("spiffe://foo", s.cacert)
	_, err = s.ds.CreateBundle(ctx, bundle2)
	s.Require().NoError(err)

	bundle3 := bundleutil.BundleProtoFromRootCA("spiffe://bar", s.cert)
	_, err = s.ds.CreateBundle(ctx, bundle3)
	s.Require().NoError(err)

	// Count all
	count, err = s.ds.CountBundles(ctx)
	s.Require().NoError(err)
	s.Require().Equal(int32(3), count)
}

func (s *PluginSuite) TestCountAttestedNodes() {
	// Count empty attested nodes
	count, err := s.ds.CountAttestedNodes(ctx)
	s.Require().NoError(err)
	s.Require().Equal(int32(0), count)

	// Create attested nodes
	node := &common.AttestedNode{
		SpiffeId:            "spiffe://example.org/foo",
		AttestationDataType: "t1",
		CertSerialNumber:    "1234",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}
	_, err = s.ds.CreateAttestedNode(ctx, node)
	s.Require().NoError(err)

	node2 := &common.AttestedNode{
		SpiffeId:            "spiffe://example.org/bar",
		AttestationDataType: "t2",
		CertSerialNumber:    "5678",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}
	_, err = s.ds.CreateAttestedNode(ctx, node2)
	s.Require().NoError(err)

	// Count all
	count, err = s.ds.CountAttestedNodes(ctx)
	s.Require().NoError(err)
	s.Require().Equal(int32(2), count)
}

func (s *PluginSuite) TestCountRegistrationEntries() {
	// Count empty registration entries
	count, err := s.ds.CountRegistrationEntries(ctx)
	s.Require().NoError(err)
	s.Require().Equal(int32(0), count)

	// Create attested nodes
	entry := &common.RegistrationEntry{
		ParentId:  "spiffe://example.org/agent",
		SpiffeId:  "spiffe://example.org/foo",
		Selectors: []*common.Selector{{Type: "a", Value: "1"}},
	}
	_, err = s.ds.CreateRegistrationEntry(ctx, entry)
	s.Require().NoError(err)

	entry2 := &common.RegistrationEntry{
		ParentId:  "spiffe://example.org/agent",
		SpiffeId:  "spiffe://example.org/bar",
		Selectors: []*common.Selector{{Type: "a", Value: "2"}},
	}
	_, err = s.ds.CreateRegistrationEntry(ctx, entry2)
	s.Require().NoError(err)

	// Count all
	count, err = s.ds.CountRegistrationEntries(ctx)
	s.Require().NoError(err)
	s.Require().Equal(int32(2), count)
}

func (s *PluginSuite) TestSetBundle() {
	// create a couple of bundles for tests. the contents don't really matter
	// as long as they are for the same trust domain but have different contents.
	bundle := bundleutil.BundleProtoFromRootCA("spiffe://foo", s.cert)
	bundle2 := bundleutil.BundleProtoFromRootCA("spiffe://foo", s.cacert)

	// ensure the bundle does not exist (it shouldn't)
	s.Require().Nil(s.fetchBundle("spiffe://foo"))

	// set the bundle and make sure it is created
	_, err := s.ds.SetBundle(ctx, bundle)
	s.Require().NoError(err)
	s.RequireProtoEqual(bundle, s.fetchBundle("spiffe://foo"))

	// set the bundle and make sure it is updated
	_, err = s.ds.SetBundle(ctx, bundle2)
	s.Require().NoError(err)
	s.RequireProtoEqual(bundle2, s.fetchBundle("spiffe://foo"))
}

func (s *PluginSuite) TestBundlePrune() {
	// Setup
	// Create new bundle with two cert (one valid and one expired)
	bundle := bundleutil.BundleProtoFromRootCAs("spiffe://foo", []*x509.Certificate{s.cert, s.cacert})
	bundle.SequenceNumber = 42

	// Add two JWT signing keys (one valid and one expired)
	expiredKeyTime, err := time.Parse(time.RFC3339, _expiredNotAfterString)
	s.Require().NoError(err)

	nonExpiredKeyTime, err := time.Parse(time.RFC3339, _validNotAfterString)
	s.Require().NoError(err)

	// middleTime is a point between the two certs expiration time
	middleTime, err := time.Parse(time.RFC3339, _middleTimeString)
	s.Require().NoError(err)

	bundle.JwtSigningKeys = []*common.PublicKey{
		{NotAfter: expiredKeyTime.Unix()},
		{NotAfter: nonExpiredKeyTime.Unix()},
	}

	// Store bundle in datastore
	_, err = s.ds.CreateBundle(ctx, bundle)
	s.Require().NoError(err)

	// Prune
	// prune non existent bundle should not return error, no bundle to prune
	expiration := time.Now()
	changed, err := s.ds.PruneBundle(ctx, "spiffe://notexistent", expiration)
	s.NoError(err)
	s.False(changed)

	// prune fails if internal prune bundle fails. For instance, if all certs are expired
	expiration = time.Now()
	changed, err = s.ds.PruneBundle(ctx, bundle.TrustDomainId, expiration)
	s.AssertGRPCStatus(err, codes.Unknown, "prune failed: would prune all certificates")
	s.False(changed)

	// prune should remove expired certs
	changed, err = s.ds.PruneBundle(ctx, bundle.TrustDomainId, middleTime)
	s.NoError(err)
	s.True(changed)

	// Fetch and verify pruned bundle is the expected
	expectedPrunedBundle := bundleutil.BundleProtoFromRootCAs("spiffe://foo", []*x509.Certificate{s.cert})
	expectedPrunedBundle.JwtSigningKeys = []*common.PublicKey{{NotAfter: nonExpiredKeyTime.Unix()}}
	expectedPrunedBundle.SequenceNumber = 43
	fb, err := s.ds.FetchBundle(ctx, "spiffe://foo")
	s.Require().NoError(err)
	s.AssertProtoEqual(expectedPrunedBundle, fb)
}

func (s *PluginSuite) TestTaintX509CA() {
	t := s.T()

	// Setup
	unusedKey := testkey.NewEC256(t)

	// Tainted public key on raw format
	certPublicKeyRaw, err := x509.MarshalPKIXPublicKey(s.cert.PublicKey)
	require.NoError(t, err)

	// Create new bundle with two certs
	bundle := bundleutil.BundleProtoFromRootCAs("spiffe://foo", []*x509.Certificate{s.cert, s.cacert})
	bundle.X509TaintedKeys = []*common.X509TaintedKey{
		{PublicKey: []byte("foh")},
	}

	// Bundle not found
	err = s.ds.TaintX509CA(ctx, "spiffe://foo", unusedKey.Public())
	spiretest.RequireGRPCStatus(t, err, codes.NotFound, _notFoundErrMsg)

	_, err = s.ds.CreateBundle(ctx, bundle)
	require.NoError(t, err)

	// Bundle contains a malformed tainted key
	err = s.ds.TaintX509CA(ctx, "spiffe://foo", unusedKey.Public())
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Internal, "failed to parse tainted Key:")

	// Remove malformed tainted key
	bundle.X509TaintedKeys = []*common.X509TaintedKey{}
	_, err = s.ds.UpdateBundle(ctx, bundle, nil)
	require.NoError(t, err)

	// Invalid public key to taint provided
	err = s.ds.TaintX509CA(ctx, "spiffe://foo", unusedKey)
	spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "failed to marshal public key to taint: x509: unsupported public key type: *ecdsa.PrivateKey")

	// Taint successfully
	err = s.ds.TaintX509CA(ctx, "spiffe://foo", s.cert.PublicKey)
	require.NoError(t, err)

	fetchedBundle, err := s.ds.FetchBundle(ctx, "spiffe://foo")
	require.NoError(t, err)

	expectedRootCAs := []*common.Certificate{
		{DerBytes: s.cert.Raw},
		{DerBytes: s.cacert.Raw},
	}

	require.Equal(t, expectedRootCAs, fetchedBundle.RootCas)

	expectedTaintedKeys := []*common.X509TaintedKey{
		{PublicKey: certPublicKeyRaw},
	}
	require.Equal(t, expectedTaintedKeys, fetchedBundle.X509TaintedKeys)

	// Not able to taint a tainted CA
	err = s.ds.TaintX509CA(ctx, "spiffe://foo", s.cert.PublicKey)
	spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "root CA is already tainted")
}

func (s *PluginSuite) TestRevokeX509CA() {
	t := s.T()

	// Setup
	unusedKey := testkey.NewRSA2048(t)

	caCertPublicKeyRaw, err := x509.MarshalPKIXPublicKey(s.cacert.PublicKey)
	require.NoError(t, err)

	// Tainted public key on raw format
	certPublicKeyRaw, err := x509.MarshalPKIXPublicKey(s.cert.PublicKey)
	require.NoError(t, err)

	keyForMalformedCert := testkey.NewEC256(t)
	malformedX509 := &x509.Certificate{
		PublicKey: keyForMalformedCert.PublicKey,
		Raw:       []byte("no a certificate"),
	}

	// Create new bundle with two cert (one valid and one expired)
	bundle := bundleutil.BundleProtoFromRootCAs("spiffe://foo", []*x509.Certificate{s.cert, s.cacert, malformedX509})
	bundle.X509TaintedKeys = []*common.X509TaintedKey{
		{PublicKey: []byte("foh")},
	}

	// Bundle not found
	err = s.ds.RevokeX509CA(ctx, "spiffe://foo", unusedKey.Public())
	spiretest.RequireGRPCStatus(t, err, codes.NotFound, _notFoundErrMsg)

	_, err = s.ds.CreateBundle(ctx, bundle)
	require.NoError(t, err)

	// Bundle contains a malformed tainted key
	err = s.ds.RevokeX509CA(ctx, "spiffe://foo", unusedKey.PublicKey)
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Internal, "failed to parse tainted Key:")

	// Remove malformed tainted key
	bundle.X509TaintedKeys = []*common.X509TaintedKey{}
	_, err = s.ds.UpdateBundle(ctx, bundle, nil)
	require.NoError(t, err)

	// // No root CA is using provided key
	// err = s.ds.RevokeX509CA(ctx, "spiffe://foo", unusedKey.PublicKey)
	// spiretest.RequireGRPCStatus(t, err, codes.NotFound, "no root CA found with provided public key")

	// No able to revoke untainted bundles
	err = s.ds.RevokeX509CA(ctx, "spiffe://foo", s.cert.PublicKey)
	spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "it is not possible to revoke an untainted root CA")

	// Mark cert as tainted
	bundle.X509TaintedKeys = []*common.X509TaintedKey{
		{PublicKey: certPublicKeyRaw},
		{PublicKey: caCertPublicKeyRaw},
	}
	_, err = s.ds.UpdateBundle(ctx, bundle, nil)
	require.NoError(t, err)

	// Bundle contains a malformed root CA
	err = s.ds.RevokeX509CA(ctx, "spiffe://foo", s.cert.PublicKey)
	spiretest.RequireGRPCStatus(t, err, codes.Internal, "failed to parse root CA: x509: malformed certificate")

	// Remove malformed root CA
	bundle.RootCas = []*common.Certificate{
		{DerBytes: s.cert.Raw},
		{DerBytes: s.cacert.Raw},
	}
	_, err = s.ds.UpdateBundle(ctx, bundle, nil)
	require.NoError(t, err)

	// Revoke successfully
	err = s.ds.RevokeX509CA(ctx, "spiffe://foo", s.cert.PublicKey)
	require.NoError(t, err)

	fetchedBunde, err := s.ds.FetchBundle(ctx, "spiffe://foo")
	require.NoError(t, err)

	expectedRootCAs := []*common.Certificate{
		{DerBytes: s.cacert.Raw},
	}
	require.Equal(t, expectedRootCAs, fetchedBunde.RootCas)

	expectedTaintedKeys := []*common.X509TaintedKey{
		{PublicKey: caCertPublicKeyRaw},
	}
	require.Equal(t, expectedTaintedKeys, fetchedBunde.X509TaintedKeys)
}

func (s *PluginSuite) TestTaintJWTKey() {
	t := s.T()
	// Setup
	// Create new bundle with two JWT Keys
	bundle := bundleutil.BundleProtoFromRootCAs("spiffe://foo", nil)
	bundle.JwtSigningKeys = []*common.PublicKey{
		{Kid: "key1"},
		{Kid: "key2"},
		{Kid: "key2"},
	}

	// Bundle not found
	publicKey, err := s.ds.TaintJWTKey(ctx, "spiffe://foo", "key1")
	spiretest.RequireGRPCStatus(t, err, codes.NotFound, _notFoundErrMsg)
	require.Nil(t, publicKey)

	_, err = s.ds.CreateBundle(ctx, bundle)
	require.NoError(t, err)

	// Bundle contains repeated key
	publicKey, err = s.ds.TaintJWTKey(ctx, "spiffe://foo", "key2")
	spiretest.RequireGRPCStatus(t, err, codes.Internal, "another JWT Key found with the same KeyID")
	require.Nil(t, publicKey)

	// Key not found
	publicKey, err = s.ds.TaintJWTKey(ctx, "spiffe://foo", "no id")
	spiretest.RequireGRPCStatus(t, err, codes.NotFound, "no JWT Key found with provided key ID")
	require.Nil(t, publicKey)

	// Taint successfully
	publicKey, err = s.ds.TaintJWTKey(ctx, "spiffe://foo", "key1")
	require.NoError(t, err)
	require.NotNil(t, publicKey)

	fetchedBundle, err := s.ds.FetchBundle(ctx, "spiffe://foo")
	require.NoError(t, err)

	expectedKeys := []*common.PublicKey{
		{Kid: "key1", TaintedKey: true},
		{Kid: "key2"},
		{Kid: "key2"},
	}
	require.Equal(t, expectedKeys, fetchedBundle.JwtSigningKeys)

	// No able to taint Key again
	publicKey, err = s.ds.TaintJWTKey(ctx, "spiffe://foo", "key1")
	spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "key is already tainted")
	require.Nil(t, publicKey)
}

func (s *PluginSuite) TestRevokeJWTKey() {
	t := s.T()
	// Setup
	// Create new bundle with two JWT Keys
	bundle := bundleutil.BundleProtoFromRootCAs("spiffe://foo", nil)
	bundle.JwtSigningKeys = []*common.PublicKey{
		{Kid: "key1"},
		{Kid: "key2"},
	}

	// Bundle not found
	publicKey, err := s.ds.RevokeJWTKey(ctx, "spiffe://foo", "key1")
	spiretest.RequireGRPCStatus(t, err, codes.NotFound, _notFoundErrMsg)
	require.Nil(t, publicKey)

	_, err = s.ds.CreateBundle(ctx, bundle)
	require.NoError(t, err)

	// Key not found
	publicKey, err = s.ds.RevokeJWTKey(ctx, "spiffe://foo", "no id")
	spiretest.RequireGRPCStatus(t, err, codes.NotFound, "no JWT Key found with provided key ID")
	require.Nil(t, publicKey)

	// No allow to revoke untainted key
	publicKey, err = s.ds.RevokeJWTKey(ctx, "spiffe://foo", "key1")
	spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "it is not possible to revoke an untainted key")
	require.Nil(t, publicKey)

	// Add a duplicated key and taint it
	bundle.JwtSigningKeys = []*common.PublicKey{
		{Kid: "key1"},
		{Kid: "key2", TaintedKey: true},
		{Kid: "key2", TaintedKey: true},
	}
	_, err = s.ds.UpdateBundle(ctx, bundle, nil)
	require.NoError(t, err)

	// No allow to revoke because a duplicated key is found
	publicKey, err = s.ds.RevokeJWTKey(ctx, "spiffe://foo", "key2")
	spiretest.RequireGRPCStatus(t, err, codes.Internal, "another key found with the same KeyID")
	require.Nil(t, publicKey)

	// Remove duplicated key
	bundle.JwtSigningKeys = []*common.PublicKey{
		{Kid: "key1"},
		{Kid: "key2", TaintedKey: true},
	}
	_, err = s.ds.UpdateBundle(ctx, bundle, nil)
	require.NoError(t, err)

	// Revoke successfully
	publicKey, err = s.ds.RevokeJWTKey(ctx, "spiffe://foo", "key2")
	require.NoError(t, err)
	require.Equal(t, &common.PublicKey{Kid: "key2", TaintedKey: true}, publicKey)

	fetchedBundle, err := s.ds.FetchBundle(ctx, "spiffe://foo")
	require.NoError(t, err)

	expectedJWTKeys := []*common.PublicKey{{Kid: "key1"}}
	require.Equal(t, expectedJWTKeys, fetchedBundle.JwtSigningKeys)
}

func (s *PluginSuite) TestCreateAttestedNode() {
	node := &common.AttestedNode{
		SpiffeId:            "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}

	attestedNode, err := s.ds.CreateAttestedNode(ctx, node)
	s.Require().NoError(err)
	s.AssertProtoEqual(node, attestedNode)

	attestedNode, err = s.ds.FetchAttestedNode(ctx, node.SpiffeId)
	s.Require().NoError(err)
	s.AssertProtoEqual(node, attestedNode)
}

func (s *PluginSuite) TestFetchAttestedNodeMissing() {
	attestedNode, err := s.ds.FetchAttestedNode(ctx, "missing")
	s.Require().NoError(err)
	s.Require().Nil(attestedNode)
}

func (s *PluginSuite) TestListAttestedNodes() {
	// Connection is never used, each test creates a connection to a different database
	s.ds.Close()

	now := time.Now()
	expired := now.Add(-time.Hour)
	unexpired := now.Add(time.Hour)

	makeAttestedNode := func(spiffeIDSuffix, attestationType string, notAfter time.Time, sn string, canReattest bool, selectors ...string) *common.AttestedNode {
		return &common.AttestedNode{
			SpiffeId:            makeID(spiffeIDSuffix),
			AttestationDataType: attestationType,
			CertSerialNumber:    sn,
			CertNotAfter:        notAfter.Unix(),
			CanReattest:         canReattest,
			Selectors:           makeSelectors(selectors...),
		}
	}

	banned := ""
	bannedFalse := false
	bannedTrue := true
	unbanned := "IRRELEVANT"

	canReattestFalse := false
	canReattestTrue := true

	nodeA := makeAttestedNode("A", "T1", expired, unbanned, false, "S1")
	nodeB := makeAttestedNode("B", "T2", expired, unbanned, false, "S1")
	nodeC := makeAttestedNode("C", "T1", expired, unbanned, false, "S2")
	nodeD := makeAttestedNode("D", "T2", expired, unbanned, false, "S2")
	nodeE := makeAttestedNode("E", "T1", unexpired, banned, false, "S1", "S2")
	nodeF := makeAttestedNode("F", "T2", unexpired, banned, false, "S1", "S3")
	nodeG := makeAttestedNode("G", "T1", unexpired, banned, false, "S2", "S3")
	nodeH := makeAttestedNode("H", "T2", unexpired, banned, false, "S2", "S3")
	nodeI := makeAttestedNode("I", "T1", unexpired, unbanned, true, "S1")

	for _, tt := range []struct {
		test                string
		nodes               []*common.AttestedNode
		pageSize            int32
		byExpiresBefore     time.Time
		byAttestationType   string
		bySelectors         *datastore.BySelectors
		byBanned            *bool
		byCanReattest       *bool
		expectNodesOut      []*common.AttestedNode
		expectPagedTokensIn []string
		expectPagedNodesOut [][]*common.AttestedNode
	}{
		{
			test:                "without attested nodes",
			expectNodesOut:      []*common.AttestedNode{},
			expectPagedTokensIn: []string{""},
			expectPagedNodesOut: [][]*common.AttestedNode{{}},
		},
		{
			test:                "with partial page",
			nodes:               []*common.AttestedNode{nodeA},
			pageSize:            2,
			expectNodesOut:      []*common.AttestedNode{nodeA},
			expectPagedTokensIn: []string{"", "1"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {}},
		},
		{
			test:                "with full page",
			nodes:               []*common.AttestedNode{nodeA, nodeB},
			pageSize:            2,
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeB},
			expectPagedTokensIn: []string{"", "2"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA, nodeB}, {}},
		},
		{
			test:                "with page and a half",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC},
			pageSize:            2,
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeB, nodeC},
			expectPagedTokensIn: []string{"", "2", "3"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA, nodeB}, {nodeC}, {}},
		},
		// By expiration
		{
			test:                "by expires before",
			nodes:               []*common.AttestedNode{nodeA, nodeE, nodeB, nodeF, nodeG, nodeC},
			byExpiresBefore:     now,
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeB, nodeC},
			expectPagedTokensIn: []string{"", "1", "3", "6"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {nodeB}, {nodeC}, {}},
		},
		// By attestation type
		{
			test:                "by attestation type",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE},
			byAttestationType:   "T1",
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeC, nodeE},
			expectPagedTokensIn: []string{"", "1", "3", "5"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {nodeC}, {nodeE}, {}},
		},
		// By banned
		{
			test:                "by banned",
			nodes:               []*common.AttestedNode{nodeA, nodeE, nodeF, nodeB},
			byBanned:            &bannedTrue,
			expectNodesOut:      []*common.AttestedNode{nodeE, nodeF},
			expectPagedTokensIn: []string{"", "2", "3"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeE}, {nodeF}, {}},
		},
		{
			test:                "by unbanned",
			nodes:               []*common.AttestedNode{nodeA, nodeE, nodeF, nodeB},
			byBanned:            &bannedFalse,
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeB},
			expectPagedTokensIn: []string{"", "1", "4"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {nodeB}, {}},
		},
		{
			test:                "banned undefined",
			nodes:               []*common.AttestedNode{nodeA, nodeE, nodeF, nodeB},
			byBanned:            nil,
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeE, nodeF, nodeB},
			expectPagedTokensIn: []string{"", "1", "2", "3", "4"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {nodeE}, {nodeF}, {nodeB}, {}},
		},
		// By selector subset
		{
			test:                "by selector subset",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:         bySelectors(datastore.Subset, "S1"),
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeB},
			expectPagedTokensIn: []string{"", "1", "2"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {nodeB}, {}},
		},
		{
			test:                "by selectors subset",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:         bySelectors(datastore.Subset, "S1", "S3"),
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeB, nodeF},
			expectPagedTokensIn: []string{"", "1", "2", "6"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {nodeB}, {nodeF}, {}},
		},
		// By exact selector exact
		{
			test:                "by selector exact",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:         bySelectors(datastore.Exact, "S1"),
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeB},
			expectPagedTokensIn: []string{"", "1", "2"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {nodeB}, {}},
		},
		{
			test:                "by selectors exact",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:         bySelectors(datastore.Exact, "S1", "S3"),
			expectNodesOut:      []*common.AttestedNode{nodeF},
			expectPagedTokensIn: []string{"", "6"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeF}, {}},
		},
		// By exact selector match any
		{
			test:                "by selector match any",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:         bySelectors(datastore.MatchAny, "S1"),
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeB, nodeE, nodeF},
			expectPagedTokensIn: []string{"", "1", "2", "5", "6"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {nodeB}, {nodeE}, {nodeF}, {}},
		},
		{
			test:                "by selectors match any",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:         bySelectors(datastore.MatchAny, "S1", "S3"),
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeB, nodeE, nodeF, nodeG, nodeH},
			expectPagedTokensIn: []string{"", "1", "2", "5", "6", "7", "8"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {nodeB}, {nodeE}, {nodeF}, {nodeG}, {nodeH}, {}},
		},
		// By exact selector superset
		{
			test:                "by selector superset",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:         bySelectors(datastore.Superset, "S1"),
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeB, nodeE, nodeF},
			expectPagedTokensIn: []string{"", "1", "2", "5", "6"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {nodeB}, {nodeE}, {nodeF}, {}},
		},
		{
			test:                "by selectors superset",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeH},
			bySelectors:         bySelectors(datastore.Superset, "S1", "S2"),
			expectNodesOut:      []*common.AttestedNode{nodeE},
			expectPagedTokensIn: []string{"", "5"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeE}, {}},
		},
		// By CanReattest=true
		{
			test:                "by CanReattest=true",
			nodes:               []*common.AttestedNode{nodeA, nodeI},
			byAttestationType:   "T1",
			bySelectors:         nil,
			byCanReattest:       &canReattestTrue,
			expectNodesOut:      []*common.AttestedNode{nodeI},
			expectPagedTokensIn: []string{"", "2"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeI}, {}},
		},
		// By CanReattest=false
		{
			test:                "by CanReattest=false",
			nodes:               []*common.AttestedNode{nodeA, nodeI},
			byAttestationType:   "T1",
			bySelectors:         nil,
			byCanReattest:       &canReattestFalse,
			expectNodesOut:      []*common.AttestedNode{nodeA},
			expectPagedTokensIn: []string{"", "1"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {}},
		},
		// By attestation type and selector subset. This is to exercise some
		// of the logic that combines these parts of the queries together to
		// make sure they glom well.
		{
			test:                "by attestation type and selector subset",
			nodes:               []*common.AttestedNode{nodeA, nodeB, nodeC, nodeD, nodeE},
			byAttestationType:   "T1",
			bySelectors:         bySelectors(datastore.Subset, "S1"),
			expectNodesOut:      []*common.AttestedNode{nodeA},
			expectPagedTokensIn: []string{"", "1"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {}},
		},
		// Exercise all filters together
		{
			test:                "all filters",
			nodes:               []*common.AttestedNode{nodeA, nodeE, nodeB, nodeF, nodeG, nodeC},
			byBanned:            &bannedFalse,
			byExpiresBefore:     now,
			byAttestationType:   "T1",
			bySelectors:         bySelectors(datastore.Subset, "S1"),
			expectNodesOut:      []*common.AttestedNode{nodeA},
			expectPagedTokensIn: []string{"", "1"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {}},
			byCanReattest:       &canReattestFalse,
		},
	} {
		tt := tt
		for _, withPagination := range []bool{true, false} {
			for _, withSelectors := range []bool{true, false} {
				name := tt.test
				if withSelectors {
					name += " with selectors"
				} else {
					name += " without selectors"
				}
				if withPagination {
					name += " with pagination"
				} else {
					name += " without pagination"
				}
				s.T().Run(name, func(t *testing.T) {
					s.ds = s.newPlugin()
					defer s.ds.Close()

					// Create entries for the test. For convenience, map the actual
					// entry ID to the "test" entry ID, so we can easily pinpoint
					// which entries were unexpectedly missing or included in the
					// listing.
					for _, node := range tt.nodes {
						_, err := s.ds.CreateAttestedNode(ctx, node)
						require.NoError(t, err)
						err = s.ds.SetNodeSelectors(ctx, node.SpiffeId, node.Selectors)
						require.NoError(t, err)
					}

					var pagination *datastore.Pagination
					if withPagination {
						pagination = &datastore.Pagination{
							PageSize: tt.pageSize,
						}
						if pagination.PageSize == 0 {
							pagination.PageSize = 1
						}
					}

					var tokensIn []string
					var actualIDsOut [][]string
					actualSelectorsOut := make(map[string][]*common.Selector)
					req := &datastore.ListAttestedNodesRequest{
						Pagination:        pagination,
						ByExpiresBefore:   tt.byExpiresBefore,
						ByAttestationType: tt.byAttestationType,
						BySelectorMatch:   tt.bySelectors,
						ByBanned:          tt.byBanned,
						ByCanReattest:     tt.byCanReattest,
						FetchSelectors:    withSelectors,
					}

					for i := 0; ; i++ {
						// Don't loop forever if there is a bug
						if i > len(tt.nodes) {
							require.FailNowf(t, "Exhausted paging limit in test", "tokens=%q spiffeids=%q", tokensIn, actualIDsOut)
						}
						if req.Pagination != nil {
							tokensIn = append(tokensIn, req.Pagination.Token)
						}
						resp, err := s.ds.ListAttestedNodes(ctx, req)
						require.NoError(t, err)
						require.NotNil(t, resp)
						if withPagination {
							require.NotNil(t, resp.Pagination, "response missing pagination")
							assert.Equal(t, req.Pagination.PageSize, resp.Pagination.PageSize, "response page size did not match request")
						} else {
							require.Nil(t, resp.Pagination, "response has pagination")
						}

						var idSet []string
						for _, node := range resp.Nodes {
							idSet = append(idSet, node.SpiffeId)
							actualSelectorsOut[node.SpiffeId] = node.Selectors
						}
						actualIDsOut = append(actualIDsOut, idSet)

						if resp.Pagination == nil || resp.Pagination.Token == "" {
							break
						}
						req.Pagination = resp.Pagination
					}

					expectNodesOut := tt.expectPagedNodesOut
					if !withPagination {
						expectNodesOut = [][]*common.AttestedNode{tt.expectNodesOut}
					}

					var expectIDsOut [][]string
					expectSelectorsOut := make(map[string][]*common.Selector)
					for _, nodeSet := range expectNodesOut {
						var idSet []string
						for _, node := range nodeSet {
							idSet = append(idSet, node.SpiffeId)
							if withSelectors {
								expectSelectorsOut[node.SpiffeId] = node.Selectors
							}
						}
						expectIDsOut = append(expectIDsOut, idSet)
					}

					if withPagination {
						assert.Equal(t, tt.expectPagedTokensIn, tokensIn, "unexpected request tokens")
					} else {
						assert.Empty(t, tokensIn, "unexpected request tokens")
					}
					assert.Equal(t, expectIDsOut, actualIDsOut, "unexpected response nodes")
					assertSelectorsEqual(t, expectSelectorsOut, actualSelectorsOut, "unexpected response selectors")
				})
			}
		}
	}
}

func (s *PluginSuite) TestUpdateAttestedNode() {
	// Current nodes values
	nodeID := "spiffe-id"
	attestationType := "attestation-data-type"
	serial := "cert-serial-number-1"
	expires := int64(1)
	newSerial := "new-cert-serial-number"
	newExpires := int64(2)

	// Updated nodes values
	updatedSerial := "cert-serial-number-2"
	updatedExpires := int64(3)
	updatedNewSerial := ""
	updatedNewExpires := int64(0)

	// This connection is never used, each plugin is creating a connection to a new database
	s.ds.Close()

	for _, tt := range []struct {
		name           string
		updateNode     *common.AttestedNode
		updateNodeMask *common.AttestedNodeMask
		expUpdatedNode *common.AttestedNode
		expCode        codes.Code
		expMsg         string
	}{
		{
			name: "update non-existing attested node",
			updateNode: &common.AttestedNode{
				SpiffeId:         "non-existent-node-id",
				CertSerialNumber: updatedSerial,
				CertNotAfter:     updatedExpires,
			},
			expCode: codes.NotFound,
			expMsg:  _notFoundErrMsg,
		},
		{
			name: "update attested node with all false mask",
			updateNode: &common.AttestedNode{
				SpiffeId:            nodeID,
				CertSerialNumber:    updatedSerial,
				CertNotAfter:        updatedExpires,
				NewCertNotAfter:     updatedNewExpires,
				NewCertSerialNumber: updatedNewSerial,
			},
			updateNodeMask: &common.AttestedNodeMask{},
			expUpdatedNode: &common.AttestedNode{
				SpiffeId:            nodeID,
				AttestationDataType: attestationType,
				CertSerialNumber:    serial,
				CertNotAfter:        expires,
				NewCertNotAfter:     newExpires,
				NewCertSerialNumber: newSerial,
			},
		},
		{
			name: "update attested node with mask set only some fields: 'CertSerialNumber', 'NewCertNotAfter'",
			updateNode: &common.AttestedNode{
				SpiffeId:            nodeID,
				CertSerialNumber:    updatedSerial,
				CertNotAfter:        updatedExpires,
				NewCertNotAfter:     updatedNewExpires,
				NewCertSerialNumber: updatedNewSerial,
			},
			updateNodeMask: &common.AttestedNodeMask{
				CertSerialNumber: true,
				NewCertNotAfter:  true,
			},
			expUpdatedNode: &common.AttestedNode{
				SpiffeId:            nodeID,
				AttestationDataType: attestationType,
				CertSerialNumber:    updatedSerial,
				CertNotAfter:        expires,
				NewCertNotAfter:     updatedNewExpires,
				NewCertSerialNumber: newSerial,
			},
		},
		{
			name: "update attested node with nil mask",
			updateNode: &common.AttestedNode{
				SpiffeId:            nodeID,
				CertSerialNumber:    updatedSerial,
				CertNotAfter:        updatedExpires,
				NewCertNotAfter:     updatedNewExpires,
				NewCertSerialNumber: updatedNewSerial,
			},
			expUpdatedNode: &common.AttestedNode{
				SpiffeId:            nodeID,
				AttestationDataType: attestationType,
				CertSerialNumber:    updatedSerial,
				CertNotAfter:        updatedExpires,
				NewCertNotAfter:     updatedNewExpires,
				NewCertSerialNumber: updatedNewSerial,
			},
		},
	} {
		tt := tt
		s.T().Run(tt.name, func(t *testing.T) {
			s.ds = s.newPlugin()
			defer s.ds.Close()

			_, err := s.ds.CreateAttestedNode(ctx, &common.AttestedNode{
				SpiffeId:            nodeID,
				AttestationDataType: attestationType,
				CertSerialNumber:    serial,
				CertNotAfter:        expires,
				NewCertNotAfter:     newExpires,
				NewCertSerialNumber: newSerial,
			})
			s.Require().NoError(err)

			// Update attested node
			updatedNode, err := s.ds.UpdateAttestedNode(ctx, tt.updateNode, tt.updateNodeMask)
			s.RequireGRPCStatus(err, tt.expCode, tt.expMsg)
			if tt.expCode != codes.OK {
				s.Require().Nil(updatedNode)
				return
			}
			s.Require().NoError(err)
			s.Require().NotNil(updatedNode)
			s.RequireProtoEqual(tt.expUpdatedNode, updatedNode)

			// Check a fresh fetch shows the updated attested node
			attestedNode, err := s.ds.FetchAttestedNode(ctx, tt.updateNode.SpiffeId)
			s.Require().NoError(err)
			s.Require().NotNil(attestedNode)
			s.RequireProtoEqual(tt.expUpdatedNode, attestedNode)
		})
	}
}

func (s *PluginSuite) TestDeleteAttestedNode() {
	entryFoo := &common.AttestedNode{
		SpiffeId:            "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}
	entryBar := &common.AttestedNode{
		SpiffeId:            "bar",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}

	s.Run("delete non-existing attested node", func() {
		_, err := s.ds.DeleteAttestedNode(ctx, entryFoo.SpiffeId)
		s.RequireGRPCStatus(err, codes.NotFound, _notFoundErrMsg)
	})

	s.Run("delete attested node that don't have selectors associated", func() {
		_, err := s.ds.CreateAttestedNode(ctx, entryFoo)
		s.Require().NoError(err)

		deletedNode, err := s.ds.DeleteAttestedNode(ctx, entryFoo.SpiffeId)
		s.Require().NoError(err)
		s.AssertProtoEqual(entryFoo, deletedNode)

		attestedNode, err := s.ds.FetchAttestedNode(ctx, entryFoo.SpiffeId)
		s.Require().NoError(err)
		s.Nil(attestedNode)
	})

	s.Run("delete attested node with associated selectors", func() {
		selectors := []*common.Selector{
			{Type: "TYPE1", Value: "VALUE1"},
			{Type: "TYPE2", Value: "VALUE2"},
			{Type: "TYPE3", Value: "VALUE3"},
			{Type: "TYPE4", Value: "VALUE4"},
		}

		_, err := s.ds.CreateAttestedNode(ctx, entryFoo)
		s.Require().NoError(err)
		// create selectors for entryFoo
		err = s.ds.SetNodeSelectors(ctx, entryFoo.SpiffeId, selectors)
		s.Require().NoError(err)
		// create selectors for entryBar
		err = s.ds.SetNodeSelectors(ctx, entryBar.SpiffeId, selectors)
		s.Require().NoError(err)

		nodeSelectors, err := s.ds.GetNodeSelectors(ctx, entryFoo.SpiffeId, datastore.RequireCurrent)
		s.Require().NoError(err)
		s.Equal(selectors, nodeSelectors)

		deletedNode, err := s.ds.DeleteAttestedNode(ctx, entryFoo.SpiffeId)
		s.Require().NoError(err)
		s.AssertProtoEqual(entryFoo, deletedNode)

		attestedNode, err := s.ds.FetchAttestedNode(ctx, deletedNode.SpiffeId)
		s.Require().NoError(err)
		s.Nil(attestedNode)

		// check that selectors for deleted node are gone
		deletedSelectors, err := s.ds.GetNodeSelectors(ctx, deletedNode.SpiffeId, datastore.RequireCurrent)
		s.Require().NoError(err)
		s.Nil(deletedSelectors)

		// check that selectors for entryBar are still there
		nodeSelectors, err = s.ds.GetNodeSelectors(ctx, entryBar.SpiffeId, datastore.RequireCurrent)
		s.Require().NoError(err)
		s.Equal(selectors, nodeSelectors)
	})
}

func (s *PluginSuite) TestNodeSelectors() {
	foo1 := []*common.Selector{
		{Type: "FOO1", Value: "1"},
	}
	foo2 := []*common.Selector{
		{Type: "FOO2", Value: "1"},
	}
	bar := []*common.Selector{
		{Type: "BAR", Value: "FIGHT"},
	}

	// assert there are no selectors for foo
	selectors := s.getNodeSelectors("foo", datastore.TolerateStale)
	s.Require().Empty(selectors)
	selectors = s.getNodeSelectors("foo", datastore.RequireCurrent)
	s.Require().Empty(selectors)

	// set selectors on foo and bar
	s.setNodeSelectors("foo", foo1)
	s.setNodeSelectors("bar", bar)

	// get foo selectors
	selectors = s.getNodeSelectors("foo", datastore.TolerateStale)
	s.RequireProtoListEqual(foo1, selectors)
	selectors = s.getNodeSelectors("foo", datastore.RequireCurrent)
	s.RequireProtoListEqual(foo1, selectors)

	// replace foo selectors
	s.setNodeSelectors("foo", foo2)
	selectors = s.getNodeSelectors("foo", datastore.TolerateStale)
	s.RequireProtoListEqual(foo2, selectors)
	selectors = s.getNodeSelectors("foo", datastore.RequireCurrent)
	s.RequireProtoListEqual(foo2, selectors)

	// delete foo selectors
	s.setNodeSelectors("foo", []*common.Selector{})
	selectors = s.getNodeSelectors("foo", datastore.TolerateStale)
	s.Require().Empty(selectors)
	selectors = s.getNodeSelectors("foo", datastore.RequireCurrent)
	s.Require().Empty(selectors)

	// get bar selectors (make sure they weren't impacted by deleting foo)
	selectors = s.getNodeSelectors("bar", datastore.TolerateStale)
	s.RequireProtoListEqual(bar, selectors)
	// get bar selectors (make sure they weren't impacted by deleting foo)
	selectors = s.getNodeSelectors("bar", datastore.RequireCurrent)
	s.RequireProtoListEqual(bar, selectors)
}

func (s *PluginSuite) TestListNodeSelectors() {
	s.T().Run("no selectors exist", func(t *testing.T) {
		req := &datastore.ListNodeSelectorsRequest{}
		resp := s.listNodeSelectors(req)
		assertSelectorsEqual(t, nil, resp.Selectors)
	})

	const numNonExpiredAttNodes = 3
	const attestationDataType = "fake_nodeattestor"
	nonExpiredAttNodes := make([]*common.AttestedNode, numNonExpiredAttNodes)
	now := time.Now()
	for i := 0; i < numNonExpiredAttNodes; i++ {
		nonExpiredAttNodes[i] = &common.AttestedNode{
			SpiffeId:            fmt.Sprintf("spiffe://example.org/non-expired-node-%d", i),
			AttestationDataType: attestationDataType,
			CertSerialNumber:    fmt.Sprintf("non-expired serial %d-1", i),
			CertNotAfter:        now.Add(time.Hour).Unix(),
			NewCertSerialNumber: fmt.Sprintf("non-expired serial %d-2", i),
			NewCertNotAfter:     now.Add(2 * time.Hour).Unix(),
		}
	}

	const numExpiredAttNodes = 2
	expiredAttNodes := make([]*common.AttestedNode, numExpiredAttNodes)
	for i := 0; i < numExpiredAttNodes; i++ {
		expiredAttNodes[i] = &common.AttestedNode{
			SpiffeId:            fmt.Sprintf("spiffe://example.org/expired-node-%d", i),
			AttestationDataType: attestationDataType,
			CertSerialNumber:    fmt.Sprintf("expired serial %d-1", i),
			CertNotAfter:        now.Add(-24 * time.Hour).Unix(),
			NewCertSerialNumber: fmt.Sprintf("expired serial %d-2", i),
			NewCertNotAfter:     now.Add(-12 * time.Hour).Unix(),
		}
	}

	allAttNodesToCreate := make([]*common.AttestedNode, 0, len(nonExpiredAttNodes)+len(expiredAttNodes))
	allAttNodesToCreate = append(allAttNodesToCreate, nonExpiredAttNodes...)
	allAttNodesToCreate = append(allAttNodesToCreate, expiredAttNodes...)
	selectorMap := make(map[string][]*common.Selector)
	for i, n := range allAttNodesToCreate {
		_, err := s.ds.CreateAttestedNode(ctx, n)
		s.Require().NoError(err)

		selectors := []*common.Selector{
			{
				Type:  "foo",
				Value: strconv.Itoa(i),
			},
		}

		s.setNodeSelectors(n.SpiffeId, selectors)
		selectorMap[n.SpiffeId] = selectors
	}

	nonExpiredSelectorsMap := make(map[string][]*common.Selector, numNonExpiredAttNodes)
	for i := 0; i < numNonExpiredAttNodes; i++ {
		spiffeID := nonExpiredAttNodes[i].SpiffeId
		nonExpiredSelectorsMap[spiffeID] = selectorMap[spiffeID]
	}

	s.T().Run("list all", func(t *testing.T) {
		req := &datastore.ListNodeSelectorsRequest{}
		resp := s.listNodeSelectors(req)
		assertSelectorsEqual(t, selectorMap, resp.Selectors)
	})

	s.T().Run("list unexpired", func(t *testing.T) {
		req := &datastore.ListNodeSelectorsRequest{
			ValidAt: now,
		}
		resp := s.listNodeSelectors(req)
		assertSelectorsEqual(t, nonExpiredSelectorsMap, resp.Selectors)
	})
}

func (s *PluginSuite) TestListNodeSelectorsGroupsBySpiffeID() {
	insertSelector := func(id int, spiffeID, selectorType, selectorValue string) {
		query := maybeRebind(s.ds.db.databaseType, "INSERT INTO node_resolver_map_entries(id, spiffe_id, type, value) VALUES (?, ?, ?, ?)")
		_, err := s.ds.db.raw.Exec(query, id, spiffeID, selectorType, selectorValue)
		s.Require().NoError(err)
	}

	// Insert selectors out of order in respect to the SPIFFE ID so
	// that we can assert that the datastore aggregates the results correctly.
	insertSelector(1, "spiffe://example.org/node3", "A", "a")
	insertSelector(2, "spiffe://example.org/node2", "B", "b")
	insertSelector(3, "spiffe://example.org/node3", "C", "c")
	insertSelector(4, "spiffe://example.org/node1", "D", "d")
	insertSelector(5, "spiffe://example.org/node2", "E", "e")
	insertSelector(6, "spiffe://example.org/node3", "F", "f")

	resp := s.listNodeSelectors(&datastore.ListNodeSelectorsRequest{})
	assertSelectorsEqual(s.T(), map[string][]*common.Selector{
		"spiffe://example.org/node1": {{Type: "D", Value: "d"}},
		"spiffe://example.org/node2": {{Type: "B", Value: "b"}, {Type: "E", Value: "e"}},
		"spiffe://example.org/node3": {{Type: "A", Value: "a"}, {Type: "C", Value: "c"}, {Type: "F", Value: "f"}},
	}, resp.Selectors)
}

func (s *PluginSuite) TestSetNodeSelectorsUnderLoad() {
	selectors := []*common.Selector{
		{Type: "TYPE", Value: "VALUE"},
	}

	const numWorkers = 20

	resultCh := make(chan error, numWorkers)
	nextID := int32(0)

	for i := 0; i < numWorkers; i++ {
		go func() {
			id := fmt.Sprintf("ID%d", atomic.AddInt32(&nextID, 1))
			for j := 0; j < 10; j++ {
				err := s.ds.SetNodeSelectors(ctx, id, selectors)
				if err != nil {
					resultCh <- err
				}
			}
			resultCh <- nil
		}()
	}

	for i := 0; i < numWorkers; i++ {
		s.Require().NoError(<-resultCh)
	}
}

func (s *PluginSuite) TestCreateRegistrationEntry() {
	now := time.Now().Unix()
	var validRegistrationEntries []*common.RegistrationEntry
	s.getTestDataFromJSONFile(filepath.Join("testdata", "valid_registration_entries.json"), &validRegistrationEntries)

	for _, validRegistrationEntry := range validRegistrationEntries {
		registrationEntry, err := s.ds.CreateRegistrationEntry(ctx, validRegistrationEntry)
		s.Require().NoError(err)
		s.Require().NotNil(registrationEntry)
		s.assertEntryEqual(s.T(), validRegistrationEntry, registrationEntry, now)
	}
}

func (s *PluginSuite) TestCreateOrReturnRegistrationEntry() {
	now := time.Now().Unix()

	for _, tt := range []struct {
		name          string
		modifyEntry   func(*common.RegistrationEntry) *common.RegistrationEntry
		expectError   string
		expectSimilar bool
	}{
		{
			name: "no entry provided",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				return nil
			},
			expectError: "datastore-sql: invalid request: missing registered entry",
		},
		{
			name: "no selectors",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				e.Selectors = nil
				return e
			},
			expectError: "datastore-sql: invalid registration entry: missing selector list",
		},
		{
			name: "no SPIFFE ID",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				e.SpiffeId = ""
				return e
			},
			expectError: "datastore-sql: invalid registration entry: missing SPIFFE ID",
		},
		{
			name: "negative X509 ttl",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				e.X509SvidTtl = -1
				return e
			},
			expectError: "datastore-sql: invalid registration entry: X509SvidTtl is not set",
		},
		{
			name: "negative JWT ttl",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				e.JwtSvidTtl = -1
				return e
			},
			expectError: "datastore-sql: invalid registration entry: JwtSvidTtl is not set",
		},
		{
			name: "create entry successfully",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				return e
			},
		},
		{
			name: "subset selectors",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				e.Selectors = []*common.Selector{
					{Type: "a", Value: "1"},
				}
				return e
			},
		},
		{
			name: "with superset selectors",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				e.Selectors = []*common.Selector{
					{Type: "a", Value: "1"},
					{Type: "b", Value: "2"},
					{Type: "c", Value: "3"},
				}
				return e
			},
		},
		{
			name: "same selectors but different SPIFFE IDs",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				e.SpiffeId = "spiffe://example.org/baz"
				return e
			},
		},
		{
			name: "failed to create similar entry",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				return e
			},
			expectSimilar: true,
		},
	} {
		s.T().Run(tt.name, func(t *testing.T) {
			entry := &common.RegistrationEntry{
				SpiffeId: "spiffe://example.org/foo",
				ParentId: "spiffe://example.org/bar",
				Selectors: []*common.Selector{
					{Type: "a", Value: "1"},
					{Type: "b", Value: "2"},
				},
				X509SvidTtl: 1,
				JwtSvidTtl:  1,
				DnsNames: []string{
					"abcd.efg",
					"somehost",
				},
			}
			entry = tt.modifyEntry(entry)

			createdEntry, alreadyExists, err := s.ds.CreateOrReturnRegistrationEntry(ctx, entry)

			require.Equal(t, tt.expectSimilar, alreadyExists)
			if tt.expectError != "" {
				require.EqualError(t, err, tt.expectError)
				require.Nil(t, createdEntry)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, createdEntry)
			s.assertEntryEqual(t, entry, createdEntry, now)
		})
	}
}

func (s *PluginSuite) TestCreateInvalidRegistrationEntry() {
	var invalidRegistrationEntries []*common.RegistrationEntry
	s.getTestDataFromJSONFile(filepath.Join("testdata", "invalid_registration_entries.json"), &invalidRegistrationEntries)

	for _, invalidRegistrationEntry := range invalidRegistrationEntries {
		registrationEntry, err := s.ds.CreateRegistrationEntry(ctx, invalidRegistrationEntry)
		s.Require().Error(err)
		s.Require().Nil(registrationEntry)
	}

	// TODO: Check that no entries have been created
}

func (s *PluginSuite) TestFetchRegistrationEntry() {
	for _, tt := range []struct {
		name  string
		entry *common.RegistrationEntry
	}{
		{
			name: "entry with dns",
			entry: &common.RegistrationEntry{
				Selectors: []*common.Selector{
					{Type: "Type1", Value: "Value1"},
					{Type: "Type2", Value: "Value2"},
					{Type: "Type3", Value: "Value3"},
				},
				SpiffeId:    "SpiffeId",
				ParentId:    "ParentId",
				X509SvidTtl: 1,
				DnsNames: []string{
					"abcd.efg",
					"somehost",
				},
			},
		},
		{
			name: "entry with store svid",
			entry: &common.RegistrationEntry{
				Selectors: []*common.Selector{
					{Type: "Type1", Value: "Value1"},
				},
				SpiffeId:    "SpiffeId",
				ParentId:    "ParentId",
				X509SvidTtl: 1,
				StoreSvid:   true,
			},
		},
		{
			name: "entry with hint",
			entry: &common.RegistrationEntry{
				Selectors: []*common.Selector{
					{Type: "Type1", Value: "Value1"},
				},
				SpiffeId:    "SpiffeId",
				ParentId:    "ParentId",
				X509SvidTtl: 1,
				Hint:        "external",
			},
		},
	} {
		tt := tt
		s.T().Run(tt.name, func(t *testing.T) {
			createdEntry, err := s.ds.CreateRegistrationEntry(ctx, tt.entry)
			s.Require().NoError(err)
			s.Require().NotNil(createdEntry)

			fetchRegistrationEntry, err := s.ds.FetchRegistrationEntry(ctx, createdEntry.EntryId)
			s.Require().NoError(err)
			s.RequireProtoEqual(createdEntry, fetchRegistrationEntry)
		})
	}
}

func (s *PluginSuite) TestPruneRegistrationEntries() {
	now := time.Now()
	entry := &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
			{Type: "Type2", Value: "Value2"},
			{Type: "Type3", Value: "Value3"},
		},
		SpiffeId:    "SpiffeId",
		ParentId:    "ParentId",
		X509SvidTtl: 1,
		EntryExpiry: now.Unix(),
	}

	createdRegistrationEntry, err := s.ds.CreateRegistrationEntry(ctx, entry)
	s.Require().NoError(err)
	fetchedRegistrationEntry := &common.RegistrationEntry{}
	defaultLastLog := spiretest.LogEntry{
		Message: "Connected to SQL database",
	}
	prunedLogMessage := "Pruned an expired registration"

	for _, tt := range []struct {
		name                      string
		time                      time.Time
		expectedRegistrationEntry *common.RegistrationEntry
		expectedLastLog           spiretest.LogEntry
	}{
		{
			name:                      "Don't prune valid entries",
			time:                      now.Add(-10 * time.Second),
			expectedRegistrationEntry: createdRegistrationEntry,
			expectedLastLog:           defaultLastLog,
		},
		{
			name:                      "Don't prune exact ExpiresBefore",
			time:                      now,
			expectedRegistrationEntry: createdRegistrationEntry,
			expectedLastLog:           defaultLastLog,
		},
		{
			name:                      "Prune old entries",
			time:                      now.Add(10 * time.Second),
			expectedRegistrationEntry: (*common.RegistrationEntry)(nil),
			expectedLastLog: spiretest.LogEntry{
				Level:   logrus.InfoLevel,
				Message: prunedLogMessage,
				Data: logrus.Fields{
					telemetry.SPIFFEID:       createdRegistrationEntry.SpiffeId,
					telemetry.ParentID:       createdRegistrationEntry.ParentId,
					telemetry.RegistrationID: createdRegistrationEntry.EntryId,
				},
			},
		},
	} {
		tt := tt
		s.T().Run(tt.name, func(t *testing.T) {
			err = s.ds.PruneRegistrationEntries(ctx, tt.time)
			require.NoError(t, err)
			fetchedRegistrationEntry, err = s.ds.FetchRegistrationEntry(ctx, createdRegistrationEntry.EntryId)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedRegistrationEntry, fetchedRegistrationEntry)

			if tt.expectedLastLog.Message == prunedLogMessage {
				spiretest.AssertLastLogs(t, s.hook.AllEntries(), []spiretest.LogEntry{tt.expectedLastLog})
			} else {
				assert.Equal(t, s.hook.LastEntry().Message, tt.expectedLastLog.Message)
			}
		})
	}
}

func (s *PluginSuite) TestFetchInexistentRegistrationEntry() {
	fetchedRegistrationEntry, err := s.ds.FetchRegistrationEntry(ctx, "INEXISTENT")
	s.Require().NoError(err)
	s.Require().Nil(fetchedRegistrationEntry)
}

func (s *PluginSuite) TestListRegistrationEntries() {
	// Connection is never used, each test creates new connection to a different database
	s.ds.Close()

	s.testListRegistrationEntries(datastore.RequireCurrent)
	s.testListRegistrationEntries(datastore.TolerateStale)

	resp, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		Pagination: &datastore.Pagination{
			PageSize: 0,
		},
	})
	s.RequireGRPCStatus(err, codes.InvalidArgument, "cannot paginate with pagesize = 0")
	s.Require().Nil(resp)

	resp, err = s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		Pagination: &datastore.Pagination{
			Token:    "invalid int",
			PageSize: 10,
		},
	})
	s.Require().Error(err, "could not parse token 'invalid int'")
	s.Require().Nil(resp)

	resp, err = s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		BySelectors: &datastore.BySelectors{},
	})
	s.RequireGRPCStatus(err, codes.InvalidArgument, "cannot list by empty selector set")
	s.Require().Nil(resp)
}

func (s *PluginSuite) testListRegistrationEntries(dataConsistency datastore.DataConsistency) {
	byFederatesWith := func(match datastore.MatchBehavior, trustDomainIDs ...string) *datastore.ByFederatesWith {
		return &datastore.ByFederatesWith{
			TrustDomains: trustDomainIDs,
			Match:        match,
		}
	}

	makeEntry := func(parentIDSuffix, spiffeIDSuffix, hint string, selectors ...string) *common.RegistrationEntry {
		return &common.RegistrationEntry{
			EntryId:   fmt.Sprintf("%s%s%s", parentIDSuffix, spiffeIDSuffix, strings.Join(selectors, "")),
			ParentId:  makeID(parentIDSuffix),
			SpiffeId:  makeID(spiffeIDSuffix),
			Selectors: makeSelectors(selectors...),
			Hint:      hint,
		}
	}

	foobarAB1 := makeEntry("foo", "bar", "external", "A", "B")
	foobarAB1.FederatesWith = []string{"spiffe://federated1.test"}
	foobarAD12 := makeEntry("foo", "bar", "", "A", "D")
	foobarAD12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}
	foobarCB2 := makeEntry("foo", "bar", "internal", "C", "B")
	foobarCB2.FederatesWith = []string{"spiffe://federated2.test"}
	foobarCD12 := makeEntry("foo", "bar", "", "C", "D")
	foobarCD12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}

	foobarB := makeEntry("foo", "bar", "", "B")

	foobuzAD1 := makeEntry("foo", "buz", "", "A", "D")
	foobuzAD1.FederatesWith = []string{"spiffe://federated1.test"}
	foobuzCD := makeEntry("foo", "buz", "", "C", "D")

	bazbarAB1 := makeEntry("baz", "bar", "", "A", "B")
	bazbarAB1.FederatesWith = []string{"spiffe://federated1.test"}
	bazbarAD12 := makeEntry("baz", "bar", "external", "A", "D")
	bazbarAD12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}
	bazbarCB2 := makeEntry("baz", "bar", "", "C", "B")
	bazbarCB2.FederatesWith = []string{"spiffe://federated2.test"}
	bazbarCD12 := makeEntry("baz", "bar", "", "C", "D")
	bazbarCD12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}
	bazbarAE3 := makeEntry("baz", "bar", "", "A", "E")
	bazbarAE3.FederatesWith = []string{"spiffe://federated3.test"}

	bazbuzAB12 := makeEntry("baz", "buz", "", "A", "B")
	bazbuzAB12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}
	bazbuzB := makeEntry("baz", "buz", "", "B")
	bazbuzCD := makeEntry("baz", "buz", "", "C", "D")

	zizzazX := makeEntry("ziz", "zaz", "", "X")

	for _, tt := range []struct {
		test                  string
		entries               []*common.RegistrationEntry
		pageSize              int32
		byParentID            string
		bySpiffeID            string
		byHint                string
		bySelectors           *datastore.BySelectors
		byFederatesWith       *datastore.ByFederatesWith
		expectEntriesOut      []*common.RegistrationEntry
		expectPagedTokensIn   []string
		expectPagedEntriesOut [][]*common.RegistrationEntry
	}{
		{
			test:                  "without entries",
			expectEntriesOut:      []*common.RegistrationEntry{},
			expectPagedTokensIn:   []string{""},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{}},
		},
		{
			test:                  "with partial page",
			entries:               []*common.RegistrationEntry{foobarAB1},
			pageSize:              2,
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1},
			expectPagedTokensIn:   []string{"", "1"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}},
		},
		{
			test:                  "with full page",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarCB2},
			pageSize:              2,
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1, foobarCB2},
			expectPagedTokensIn:   []string{"", "2"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1, foobarCB2}, {}},
		},
		{
			test:                  "with page and a half",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarCB2, foobarAD12},
			pageSize:              2,
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1, foobarCB2, foobarAD12},
			expectPagedTokensIn:   []string{"", "2", "3"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1, foobarCB2}, {foobarAD12}, {}},
		},
		// by parent ID
		{
			test:                  "by parent ID",
			entries:               []*common.RegistrationEntry{foobarAB1, bazbarAD12, foobarCB2, bazbarCD12},
			byParentID:            makeID("foo"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1, foobarCB2},
			expectPagedTokensIn:   []string{"", "1", "3"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarCB2}, {}},
		},
		// by SPIFFE ID
		{
			test:                  "by SPIFFE ID",
			entries:               []*common.RegistrationEntry{foobarAB1, foobuzAD1, foobarCB2, foobuzCD},
			bySpiffeID:            makeID("bar"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1, foobarCB2},
			expectPagedTokensIn:   []string{"", "1", "3"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarCB2}, {}},
		},
		// by Hint
		{
			test:                  "by Hint, two matches",
			entries:               []*common.RegistrationEntry{foobarAB1, bazbarAD12, foobarCB2, bazbarCD12},
			byHint:                "external",
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1, bazbarAD12},
			expectPagedTokensIn:   []string{"", "1", "2"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {bazbarAD12}, {}},
		},
		{
			test:                  "by Hint, no match",
			entries:               []*common.RegistrationEntry{foobarAB1, bazbarAD12, foobarCB2, bazbarCD12},
			byHint:                "none",
			expectEntriesOut:      []*common.RegistrationEntry{},
			expectPagedTokensIn:   []string{""},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{}},
		},
		// by federates with
		{
			test:                  "by federatesWith one subset",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX},
			byFederatesWith:       byFederatesWith(datastore.Subset, "spiffe://federated1.test"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1},
			expectPagedTokensIn:   []string{"", "1"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}},
		},
		{
			test:                  "by federatesWith many subset",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX},
			byFederatesWith:       byFederatesWith(datastore.Subset, "spiffe://federated2.test", "spiffe://federated3.test"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarCB2},
			expectPagedTokensIn:   []string{"", "3"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarCB2}, {}},
		},
		{
			test:                  "by federatesWith one exact",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX},
			byFederatesWith:       byFederatesWith(datastore.Exact, "spiffe://federated1.test"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1},
			expectPagedTokensIn:   []string{"", "1"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}},
		},
		{
			test:                  "by federatesWith many exact",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX},
			byFederatesWith:       byFederatesWith(datastore.Exact, "spiffe://federated1.test", "spiffe://federated2.test"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAD12, foobarCD12},
			expectPagedTokensIn:   []string{"", "2", "4"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAD12}, {foobarCD12}, {}},
		},
		{
			test:                  "by federatesWith one match any",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX},
			byFederatesWith:       byFederatesWith(datastore.MatchAny, "spiffe://federated1.test"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCD12},
			expectPagedTokensIn:   []string{"", "1", "2", "4"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarAD12}, {foobarCD12}, {}},
		},
		{
			test:                  "by federatesWith many match any",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX},
			byFederatesWith:       byFederatesWith(datastore.MatchAny, "spiffe://federated1.test", "spiffe://federated2.test"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12},
			expectPagedTokensIn:   []string{"", "1", "2", "3", "4"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarAD12}, {foobarCB2}, {foobarCD12}, {}},
		},
		{
			test:                  "by federatesWith one superset",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX},
			byFederatesWith:       byFederatesWith(datastore.Superset, "spiffe://federated1.test"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCD12},
			expectPagedTokensIn:   []string{"", "1", "2", "4"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarAD12}, {foobarCD12}, {}},
		},
		{
			test:                  "by federatesWith many superset",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX},
			byFederatesWith:       byFederatesWith(datastore.Superset, "spiffe://federated1.test", "spiffe://federated2.test"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAD12, foobarCD12},
			expectPagedTokensIn:   []string{"", "2", "4"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAD12}, {foobarCD12}, {}},
		},
		// by parent ID and spiffe ID
		{
			test:                  "by parent ID and SPIFFE ID",
			entries:               []*common.RegistrationEntry{foobarAB1, foobuzAD1, bazbarCB2, bazbuzCD},
			byParentID:            makeID("foo"),
			bySpiffeID:            makeID("bar"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1},
			expectPagedTokensIn:   []string{"", "1"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}},
		},
		// by parent ID and selector
		{
			test:                  "by parent ID and exact selector",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12},
			byParentID:            makeID("foo"),
			bySelectors:           bySelectors(datastore.Exact, "B"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarB},
			expectPagedTokensIn:   []string{"", "1"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {}},
		},
		{
			test:                  "by parent ID and exact selectors",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12},
			byParentID:            makeID("foo"),
			bySelectors:           bySelectors(datastore.Exact, "A", "B"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1},
			expectPagedTokensIn:   []string{"", "2"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}},
		},
		{
			test:                  "by parent ID and subset selector",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12},
			byParentID:            makeID("foo"),
			bySelectors:           bySelectors(datastore.Subset, "B"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarB},
			expectPagedTokensIn:   []string{"", "1"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {}},
		},
		{
			test:                  "by parent ID and subset selectors",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD},
			byParentID:            makeID("foo"),
			bySelectors:           bySelectors(datastore.Subset, "A", "B", "Z"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarB, foobarAB1},
			expectPagedTokensIn:   []string{"", "1", "2"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {foobarAB1}, {}},
		},
		{
			test:                  "by parent ID and subset selectors no match",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD},
			byParentID:            makeID("foo"),
			bySelectors:           bySelectors(datastore.Subset, "C", "Z"),
			expectEntriesOut:      []*common.RegistrationEntry{},
			expectPagedTokensIn:   []string{""},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{}},
		},
		{
			test:                  "by parent ID and match any selector",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, foobarCD12, bazbuzB, bazbuzAB12},
			byParentID:            makeID("foo"),
			bySelectors:           bySelectors(datastore.MatchAny, "B"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarB, foobarAB1},
			expectPagedTokensIn:   []string{"", "1", "2"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {foobarAB1}, {}},
		},
		{
			test:                  "by parent ID and match any selectors",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, foobarCD12, bazbarCB2, bazbuzCD},
			byParentID:            makeID("foo"),
			bySelectors:           bySelectors(datastore.MatchAny, "A", "C", "Z"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1, foobarCD12},
			expectPagedTokensIn:   []string{"", "2", "3"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarCD12}, {}},
		},
		{
			test:                  "by parent ID and match any selectors no match",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD},
			byParentID:            makeID("foo"),
			bySelectors:           bySelectors(datastore.MatchAny, "D", "Z"),
			expectEntriesOut:      []*common.RegistrationEntry{},
			expectPagedTokensIn:   []string{""},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{}},
		},

		{
			test:                  "by parent ID and superset selector",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, foobarCD12, bazbuzB, bazbuzAB12},
			byParentID:            makeID("foo"),
			bySelectors:           bySelectors(datastore.Superset, "A"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1},
			expectPagedTokensIn:   []string{"", "2"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}},
		},
		{
			test:                  "by parent ID and superset selectors",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, foobarCD12, bazbarCB2, bazbuzCD},
			byParentID:            makeID("foo"),
			bySelectors:           bySelectors(datastore.Superset, "A", "B"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1},
			expectPagedTokensIn:   []string{"", "2"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}},
		},
		{
			test:                  "by parent ID and superset selectors no match",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD},
			byParentID:            makeID("foo"),
			bySelectors:           bySelectors(datastore.Superset, "A", "B", "Z"),
			expectEntriesOut:      []*common.RegistrationEntry{},
			expectPagedTokensIn:   []string{""},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{}},
		},
		// by parent ID and federates with
		{
			test:                  "by parentID and federatesWith one subset",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12},
			byParentID:            makeID("baz"),
			byFederatesWith:       byFederatesWith(datastore.Subset, "spiffe://federated1.test"),
			expectEntriesOut:      []*common.RegistrationEntry{bazbarAB1},
			expectPagedTokensIn:   []string{"", "6"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAB1}, {}},
		},
		{
			test:                  "by parentID and federatesWith many subset",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12},
			byParentID:            makeID("baz"),
			byFederatesWith:       byFederatesWith(datastore.Subset, "spiffe://federated2.test", "spiffe://federated3.test"),
			expectEntriesOut:      []*common.RegistrationEntry{bazbarCB2},
			expectPagedTokensIn:   []string{"", "8"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarCB2}, {}},
		},
		{
			test:                  "by parentID and federatesWith one exact",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12},
			byParentID:            makeID("baz"),
			byFederatesWith:       byFederatesWith(datastore.Exact, "spiffe://federated1.test"),
			expectEntriesOut:      []*common.RegistrationEntry{bazbarAB1},
			expectPagedTokensIn:   []string{"", "6"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAB1}, {}},
		},
		{
			test:                  "by parentID and federatesWith many exact",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12},
			byParentID:            makeID("baz"),
			byFederatesWith:       byFederatesWith(datastore.Exact, "spiffe://federated1.test", "spiffe://federated2.test"),
			expectEntriesOut:      []*common.RegistrationEntry{bazbarAD12, bazbarCD12},
			expectPagedTokensIn:   []string{"", "7", "9"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAD12}, {bazbarCD12}, {}},
		},
		{
			test:                  "by parentID and federatesWith one match any",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, bazbarAE3},
			byParentID:            makeID("baz"),
			byFederatesWith:       byFederatesWith(datastore.MatchAny, "spiffe://federated1.test"),
			expectEntriesOut:      []*common.RegistrationEntry{bazbarAB1, bazbarAD12, bazbarCD12},
			expectPagedTokensIn:   []string{"", "6", "7", "9"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAB1}, {bazbarAD12}, {bazbarCD12}, {}},
		},
		{
			test:                  "by parentID and federatesWith many match any",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, bazbarAE3},
			byParentID:            makeID("baz"),
			byFederatesWith:       byFederatesWith(datastore.MatchAny, "spiffe://federated1.test", "spiffe://federated2.test"),
			expectEntriesOut:      []*common.RegistrationEntry{bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12},
			expectPagedTokensIn:   []string{"", "6", "7", "8", "9"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAB1}, {bazbarAD12}, {bazbarCB2}, {bazbarCD12}, {}},
		},
		{
			test:                  "by parentID and federatesWith one superset",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, bazbarAE3},
			byParentID:            makeID("baz"),
			byFederatesWith:       byFederatesWith(datastore.Superset, "spiffe://federated1.test"),
			expectEntriesOut:      []*common.RegistrationEntry{bazbarAB1, bazbarAD12, bazbarCD12},
			expectPagedTokensIn:   []string{"", "6", "7", "9"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAB1}, {bazbarAD12}, {bazbarCD12}, {}},
		},
		{
			test:                  "by parentID and federatesWith many superset",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, bazbarAE3},
			byParentID:            makeID("baz"),
			byFederatesWith:       byFederatesWith(datastore.Superset, "spiffe://federated1.test", "spiffe://federated2.test"),
			expectEntriesOut:      []*common.RegistrationEntry{bazbarAD12, bazbarCD12},
			expectPagedTokensIn:   []string{"", "7", "9"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAD12}, {bazbarCD12}, {}},
		},
		// by SPIFFE ID and selector
		{
			test:                  "by SPIFFE ID and exact selector",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12},
			bySpiffeID:            makeID("bar"),
			bySelectors:           bySelectors(datastore.Exact, "B"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarB},
			expectPagedTokensIn:   []string{"", "1"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {}},
		},
		{
			test:                  "by SPIFFE ID and exact selectors",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12},
			bySpiffeID:            makeID("bar"),
			bySelectors:           bySelectors(datastore.Exact, "A", "B"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1},
			expectPagedTokensIn:   []string{"", "2"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}},
		},
		{
			test:                  "by SPIFFE ID and subset selector",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12},
			bySpiffeID:            makeID("bar"),
			bySelectors:           bySelectors(datastore.Subset, "B"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarB},
			expectPagedTokensIn:   []string{"", "1"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {}},
		},
		{
			test:                  "by SPIFFE ID and subset selectors",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD},
			bySpiffeID:            makeID("bar"),
			bySelectors:           bySelectors(datastore.Subset, "A", "B", "Z"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarB, foobarAB1},
			expectPagedTokensIn:   []string{"", "1", "2"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {foobarAB1}, {}},
		},
		{
			test:                  "by SPIFFE ID and subset selectors no match",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD},
			bySpiffeID:            makeID("bar"),
			bySelectors:           bySelectors(datastore.Subset, "C", "Z"),
			expectEntriesOut:      []*common.RegistrationEntry{},
			expectPagedTokensIn:   []string{""},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{}},
		},
		{
			test:                  "by SPIFFE ID and match any selector",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12},
			bySpiffeID:            makeID("bar"),
			bySelectors:           bySelectors(datastore.MatchAny, "A"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1},
			expectPagedTokensIn:   []string{"", "2"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}},
		},
		{
			test:                  "by SPIFFE ID and match any selectors",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD},
			bySpiffeID:            makeID("bar"),
			bySelectors:           bySelectors(datastore.MatchAny, "A", "B", "Z"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2},
			expectPagedTokensIn:   []string{"", "1", "2", "3"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {foobarAB1}, {bazbarCB2}, {}},
		},
		{
			test:                  "by SPIFFE ID and match any selectors no match",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD},
			bySpiffeID:            makeID("bar"),
			bySelectors:           bySelectors(datastore.MatchAny, "Z"),
			expectEntriesOut:      []*common.RegistrationEntry{},
			expectPagedTokensIn:   []string{""},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{}},
		},
		{
			test:                  "by SPIFFE ID and superset selector",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB12},
			bySpiffeID:            makeID("bar"),
			bySelectors:           bySelectors(datastore.Superset, "B"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarB, foobarAB1},
			expectPagedTokensIn:   []string{"", "1", "2"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {foobarAB1}, {}},
		},
		{
			test:                  "by SPIFFE ID and superset selectors",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD},
			bySpiffeID:            makeID("bar"),
			bySelectors:           bySelectors(datastore.Superset, "A", "B"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1},
			expectPagedTokensIn:   []string{"", "2"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}},
		},
		{
			test:                  "by SPIFFE ID and superset selectors no match",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD},
			bySpiffeID:            makeID("bar"),
			bySelectors:           bySelectors(datastore.Superset, "A", "B", "Z"),
			expectEntriesOut:      []*common.RegistrationEntry{},
			expectPagedTokensIn:   []string{""},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{}},
		},
		// by spiffe ID and federates with
		{
			test:                  "by SPIFFE ID and federatesWith one subset",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12},
			bySpiffeID:            makeID("bar"),
			byFederatesWith:       byFederatesWith(datastore.Subset, "spiffe://federated1.test"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1, bazbarAB1},
			expectPagedTokensIn:   []string{"", "1", "6"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {bazbarAB1}, {}},
		},
		{
			test:                  "by SPIFFE ID and federatesWith many subset",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12},
			bySpiffeID:            makeID("bar"),
			byFederatesWith:       byFederatesWith(datastore.Subset, "spiffe://federated2.test", "spiffe://federated3.test"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarCB2, bazbarCB2},
			expectPagedTokensIn:   []string{"", "3", "8"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarCB2}, {bazbarCB2}, {}},
		},
		{
			test:                  "by SPIFFE ID and federatesWith one exact",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12},
			bySpiffeID:            makeID("bar"),
			byFederatesWith:       byFederatesWith(datastore.Exact, "spiffe://federated1.test"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1, bazbarAB1},
			expectPagedTokensIn:   []string{"", "1", "6"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {bazbarAB1}, {}},
		},
		{
			test:                  "by SPIFFE ID and federatesWith many exact",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12},
			bySpiffeID:            makeID("bar"),
			byFederatesWith:       byFederatesWith(datastore.Exact, "spiffe://federated1.test", "spiffe://federated2.test"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAD12, foobarCD12, bazbarAD12, bazbarCD12},
			expectPagedTokensIn:   []string{"", "2", "4", "7", "9"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAD12}, {foobarCD12}, {bazbarAD12}, {bazbarCD12}, {}},
		},
		{
			test:                  "by SPIFFE ID and federatesWith subset no results",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12},
			bySpiffeID:            makeID("buz"),
			byFederatesWith:       byFederatesWith(datastore.Subset, "spiffe://federated2.test", "spiffe://federated3.test"),
			expectEntriesOut:      []*common.RegistrationEntry{},
			expectPagedTokensIn:   []string{""},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{}},
		},
		{
			test:                  "by SPIFFE ID and federatesWith match any",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12},
			bySpiffeID:            makeID("bar"),
			byFederatesWith:       byFederatesWith(datastore.MatchAny, "spiffe://federated1.test"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCD12, bazbarAB1, bazbarAD12, bazbarCD12},
			expectPagedTokensIn:   []string{"", "1", "2", "4", "6", "7", "9"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarAD12}, {foobarCD12}, {bazbarAB1}, {bazbarAD12}, {bazbarCD12}, {}},
		},
		{
			test:                  "by SPIFFE ID and federatesWith many match any",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12},
			bySpiffeID:            makeID("bar"),
			byFederatesWith:       byFederatesWith(datastore.MatchAny, "spiffe://federated1.test", "spiffe://federated2.test"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12},
			expectPagedTokensIn:   []string{"", "1", "2", "3", "4", "6", "7", "8", "9"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarAD12}, {foobarCB2}, {foobarCD12}, {bazbarAB1}, {bazbarAD12}, {bazbarCB2}, {bazbarCD12}, {}},
		},
		{
			test:                  "by SPIFFE ID and federatesWith match any no results",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12},
			bySpiffeID:            makeID("buz"),
			byFederatesWith:       byFederatesWith(datastore.MatchAny, "spiffe://federated3.test"),
			expectEntriesOut:      []*common.RegistrationEntry{},
			expectPagedTokensIn:   []string{""},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{}},
		},
		{
			test:                  "by SPIFFE ID and federatesWith superset",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12},
			bySpiffeID:            makeID("bar"),
			byFederatesWith:       byFederatesWith(datastore.Superset, "spiffe://federated1.test"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCD12, bazbarAB1, bazbarAD12, bazbarCD12},
			expectPagedTokensIn:   []string{"", "1", "2", "4", "6", "7", "9"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarAD12}, {foobarCD12}, {bazbarAB1}, {bazbarAD12}, {bazbarCD12}, {}},
		},
		{
			test:                  "by SPIFFE ID and federatesWith many superset",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12},
			bySpiffeID:            makeID("bar"),
			byFederatesWith:       byFederatesWith(datastore.Superset, "spiffe://federated1.test", "spiffe://federated2.test"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAD12, foobarCD12, bazbarAD12, bazbarCD12},
			expectPagedTokensIn:   []string{"", "2", "4", "7", "9"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAD12}, {foobarCD12}, {bazbarAD12}, {bazbarCD12}, {}},
		},
		{
			test:                  "by SPIFFE ID and federatesWith superset no results",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12, foobuzAD1, bazbuzAB12},
			bySpiffeID:            makeID("buz"),
			byFederatesWith:       byFederatesWith(datastore.Superset, "spiffe://federated2.test", "spiffe://federated3.test"),
			expectEntriesOut:      []*common.RegistrationEntry{},
			expectPagedTokensIn:   []string{""},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{}},
		},
		// Make sure ByFedaratesWith and BySelectors can be used together
		{
			test:                  "by Parent ID, federatesWith and selectors",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12},
			byParentID:            makeID("foo"),
			byFederatesWith:       byFederatesWith(datastore.Subset, "spiffe://federated1.test", "spiffe://federated2.test"),
			bySelectors:           bySelectors(datastore.Subset, "A", "D"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAD12},
			expectPagedTokensIn:   []string{"", "2"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAD12}, {}},
		},
	} {
		tt := tt
		for _, withPagination := range []bool{true, false} {
			name := tt.test
			if withPagination {
				name += " with pagination"
			} else {
				name += " without pagination"
			}
			if dataConsistency == datastore.TolerateStale {
				name += " read-only"
			}
			s.T().Run(name, func(t *testing.T) {
				s.ds = s.newPlugin()
				defer s.ds.Close()

				s.createBundle("spiffe://federated1.test")
				s.createBundle("spiffe://federated2.test")
				s.createBundle("spiffe://federated3.test")

				// Create entries for the test. For convenience, map the actual
				// entry ID to the "test" entry ID, so we can easily pinpoint
				// which entries were unexpectedly missing or included in the
				// listing.
				entryIDMap := map[string]string{}
				for _, entryIn := range tt.entries {
					entryOut := s.createRegistrationEntry(entryIn)
					entryIDMap[entryOut.EntryId] = entryIn.EntryId
				}

				// Optionally sleep to give time for the entries to propagate to
				// the replicas.
				if dataConsistency == datastore.TolerateStale && s.readOnlyDelay > 0 {
					time.Sleep(s.readOnlyDelay)
				}

				var pagination *datastore.Pagination
				if withPagination {
					pagination = &datastore.Pagination{
						PageSize: tt.pageSize,
					}
					if pagination.PageSize == 0 {
						pagination.PageSize = 1
					}
				}

				var tokensIn []string
				var actualEntriesOut = make(map[string]*common.RegistrationEntry)
				var expectedEntriesOut = make(map[string]*common.RegistrationEntry)
				req := &datastore.ListRegistrationEntriesRequest{
					Pagination:      pagination,
					ByParentID:      tt.byParentID,
					BySpiffeID:      tt.bySpiffeID,
					BySelectors:     tt.bySelectors,
					ByFederatesWith: tt.byFederatesWith,
					ByHint:          tt.byHint,
				}

				for i := 0; ; i++ {
					// Don't loop forever if there is a bug
					if i > len(tt.entries) {
						require.FailNowf(t, "Exhausted paging limit in test", "tokens=%q spiffeids=%q", tokensIn, actualEntriesOut)
					}
					if req.Pagination != nil {
						tokensIn = append(tokensIn, req.Pagination.Token)
					}
					resp, err := s.ds.ListRegistrationEntries(ctx, req)
					require.NoError(t, err)
					require.NotNil(t, resp)
					if withPagination {
						require.NotNil(t, resp.Pagination, "response missing pagination")
						assert.Equal(t, req.Pagination.PageSize, resp.Pagination.PageSize, "response page size did not match request")
					} else {
						assert.Nil(t, resp.Pagination, "response has pagination")
					}

					for _, entry := range resp.Entries {
						entryID, ok := entryIDMap[entry.EntryId]
						require.True(t, ok, "entry with id %q was not created by this test", entry.EntryId)
						entry.EntryId = entryID
						actualEntriesOut[entryID] = entry
					}

					if resp.Pagination == nil || resp.Pagination.Token == "" {
						break
					}
					req.Pagination = resp.Pagination
				}

				expectEntriesOut := tt.expectPagedEntriesOut
				if !withPagination {
					expectEntriesOut = [][]*common.RegistrationEntry{tt.expectEntriesOut}
				}

				for _, entrySet := range expectEntriesOut {
					for _, entry := range entrySet {
						expectedEntriesOut[entry.EntryId] = entry
					}
				}

				if withPagination {
					assert.Equal(t, tt.expectPagedTokensIn, tokensIn, "unexpected request tokens")
				} else {
					assert.Empty(t, tokensIn, "unexpected request tokens")
				}

				assert.Len(t, actualEntriesOut, len(expectedEntriesOut), "unexpected number of entries returned")
				for id, expectedEntry := range expectedEntriesOut {
					if _, ok := actualEntriesOut[id]; !ok {
						t.Errorf("Expected entry %q not found", id)
						continue
					}
					// Some databases are not returning federated IDs in the same order (e.g. mysql)
					sort.Strings(actualEntriesOut[id].FederatesWith)
					s.assertCreatedAtField(actualEntriesOut[id], expectedEntry.CreatedAt)
					spiretest.AssertProtoEqual(t, expectedEntry, actualEntriesOut[id])
				}
			})
		}
	}
}

func (s *PluginSuite) TestListRegistrationEntriesWhenCruftRowsExist() {
	_, err := s.ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "TYPE", Value: "VALUE"},
		},
		SpiffeId: "SpiffeId",
		ParentId: "ParentId",
		DnsNames: []string{
			"abcd.efg",
			"somehost",
		},
	})
	s.Require().NoError(err)

	// This is gross. Since the bug that left selectors around has been fixed
	// (#1191), I'm not sure how else to test this other than just sneaking in
	// there and removing the registered_entries row.
	res, err := s.ds.db.raw.Exec("DELETE FROM registered_entries")
	s.Require().NoError(err)
	rowsAffected, err := res.RowsAffected()
	s.Require().NoError(err)
	s.Require().Equal(int64(1), rowsAffected)

	// Assert that no rows are returned.
	resp, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	s.Require().NoError(err)
	s.Require().Empty(resp.Entries)
}

func (s *PluginSuite) TestUpdateRegistrationEntry() {
	entry := s.createRegistrationEntry(&common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
			{Type: "Type2", Value: "Value2"},
			{Type: "Type3", Value: "Value3"},
		},
		SpiffeId:    "spiffe://example.org/foo",
		ParentId:    "spiffe://example.org/bar",
		X509SvidTtl: 1,
		JwtSvidTtl:  20,
	})

	entry.X509SvidTtl = 11
	entry.JwtSvidTtl = 21
	entry.Admin = true
	entry.Downstream = true
	entry.Hint = "internal"

	updatedRegistrationEntry, err := s.ds.UpdateRegistrationEntry(ctx, entry, nil)
	s.Require().NoError(err)
	// Verify output has expected values
	s.Require().Equal(int32(11), updatedRegistrationEntry.X509SvidTtl)
	s.Require().Equal(int32(21), updatedRegistrationEntry.JwtSvidTtl)
	s.Require().True(updatedRegistrationEntry.Admin)
	s.Require().True(updatedRegistrationEntry.Downstream)
	s.Require().Equal("internal", updatedRegistrationEntry.Hint)
	s.Require().Equal(entry.CreatedAt, updatedRegistrationEntry.CreatedAt)

	registrationEntry, err := s.ds.FetchRegistrationEntry(ctx, entry.EntryId)
	s.Require().NoError(err)
	s.Require().NotNil(registrationEntry)
	s.RequireProtoEqual(updatedRegistrationEntry, registrationEntry)

	entry.EntryId = "badid"
	_, err = s.ds.UpdateRegistrationEntry(ctx, entry, nil)
	s.RequireGRPCStatus(err, codes.NotFound, _notFoundErrMsg)
}

func (s *PluginSuite) TestUpdateRegistrationEntryWithStoreSvid() {
	entry := s.createRegistrationEntry(&common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
			{Type: "Type1", Value: "Value2"},
			{Type: "Type1", Value: "Value3"},
		},
		SpiffeId:    "spiffe://example.org/foo",
		ParentId:    "spiffe://example.org/bar",
		X509SvidTtl: 1,
	})

	entry.StoreSvid = true

	updateRegistrationEntry, err := s.ds.UpdateRegistrationEntry(ctx, entry, nil)
	s.Require().NoError(err)
	s.Require().NotNil(updateRegistrationEntry)
	// Verify output has expected values
	s.Require().True(entry.StoreSvid)

	fetchRegistrationEntry, err := s.ds.FetchRegistrationEntry(ctx, entry.EntryId)
	s.Require().NoError(err)
	s.RequireProtoEqual(updateRegistrationEntry, fetchRegistrationEntry)

	// Update with invalid selectors
	entry.Selectors = []*common.Selector{
		{Type: "Type1", Value: "Value1"},
		{Type: "Type1", Value: "Value2"},
		{Type: "Type2", Value: "Value3"},
	}
	resp, err := s.ds.UpdateRegistrationEntry(ctx, entry, nil)
	s.Require().Nil(resp)
	s.Require().EqualError(err, "rpc error: code = Unknown desc = datastore-sql: invalid registration entry: selector types must be the same when store SVID is enabled")
}

func (s *PluginSuite) TestUpdateRegistrationEntryWithMask() {
	// There are 11 fields in a registration entry. Of these, 5 have some validation in the SQL
	// layer. In this test, we update each of the 11 fields and make sure update works, and also check
	// with the mask value false to make sure nothing changes. For the 5 fields that have validation
	// we try with good data, bad data, and with or without a mask (so 4 cases each.)

	// Note that most of the input validation is done in the API layer and has more extensive tests there.
	now := time.Now().Unix()
	oldEntry := &common.RegistrationEntry{
		ParentId:      "spiffe://example.org/oldParentId",
		SpiffeId:      "spiffe://example.org/oldSpiffeId",
		X509SvidTtl:   1000,
		JwtSvidTtl:    3000,
		Selectors:     []*common.Selector{{Type: "Type1", Value: "Value1"}},
		FederatesWith: []string{"spiffe://dom1.org"},
		Admin:         false,
		EntryExpiry:   1000,
		DnsNames:      []string{"dns1"},
		Downstream:    false,
		StoreSvid:     false,
	}
	newEntry := &common.RegistrationEntry{
		ParentId:      "spiffe://example.org/oldParentId",
		SpiffeId:      "spiffe://example.org/newSpiffeId",
		X509SvidTtl:   4000,
		JwtSvidTtl:    6000,
		Selectors:     []*common.Selector{{Type: "Type2", Value: "Value2"}},
		FederatesWith: []string{"spiffe://dom2.org"},
		Admin:         false,
		EntryExpiry:   1000,
		DnsNames:      []string{"dns2"},
		Downstream:    false,
		StoreSvid:     true,
		Hint:          "internal",
	}
	badEntry := &common.RegistrationEntry{
		ParentId:      "not a good parent id",
		SpiffeId:      "",
		X509SvidTtl:   -1000,
		JwtSvidTtl:    -3000,
		Selectors:     []*common.Selector{},
		FederatesWith: []string{"invalid federated bundle"},
		Admin:         false,
		EntryExpiry:   -2000,
		DnsNames:      []string{"this is a bad domain name "},
		Downstream:    false,
	}
	// Needed for the FederatesWith field to work
	s.createBundle("spiffe://dom1.org")
	s.createBundle("spiffe://dom2.org")

	var id string
	for _, testcase := range []struct {
		name   string
		mask   *common.RegistrationEntryMask
		update func(*common.RegistrationEntry)
		result func(*common.RegistrationEntry)
		err    error
	}{ // SPIFFE ID FIELD -- this field is validated so we check with good and bad data
		{name: "Update Spiffe ID, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{SpiffeId: true},
			update: func(e *common.RegistrationEntry) { e.SpiffeId = newEntry.SpiffeId },
			result: func(e *common.RegistrationEntry) { e.SpiffeId = newEntry.SpiffeId }},
		{name: "Update Spiffe ID, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{SpiffeId: false},
			update: func(e *common.RegistrationEntry) { e.SpiffeId = newEntry.SpiffeId },
			result: func(e *common.RegistrationEntry) {}},
		{name: "Update Spiffe ID, Bad Data, Mask True",
			mask:   &common.RegistrationEntryMask{SpiffeId: true},
			update: func(e *common.RegistrationEntry) { e.SpiffeId = badEntry.SpiffeId },
			err:    errors.New("invalid registration entry: missing SPIFFE ID")},
		{name: "Update Spiffe ID, Bad Data, Mask False",
			mask:   &common.RegistrationEntryMask{SpiffeId: false},
			update: func(e *common.RegistrationEntry) { e.SpiffeId = badEntry.SpiffeId },
			result: func(e *common.RegistrationEntry) {}},
		// PARENT ID FIELD -- This field isn't validated so we just check with good data
		{name: "Update Parent ID, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{ParentId: true},
			update: func(e *common.RegistrationEntry) { e.ParentId = newEntry.ParentId },
			result: func(e *common.RegistrationEntry) { e.ParentId = newEntry.ParentId }},
		{name: "Update Parent ID, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{ParentId: false},
			update: func(e *common.RegistrationEntry) { e.ParentId = newEntry.ParentId },
			result: func(e *common.RegistrationEntry) {}},
		// X509 SVID TTL FIELD -- This field is validated so we check with good and bad data
		{name: "Update X509 SVID TTL, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{X509SvidTtl: true},
			update: func(e *common.RegistrationEntry) { e.X509SvidTtl = newEntry.X509SvidTtl },
			result: func(e *common.RegistrationEntry) { e.X509SvidTtl = newEntry.X509SvidTtl }},
		{name: "Update X509 SVID TTL, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{X509SvidTtl: false},
			update: func(e *common.RegistrationEntry) { e.X509SvidTtl = badEntry.X509SvidTtl },
			result: func(e *common.RegistrationEntry) {}},
		{name: "Update X509 SVID TTL, Bad Data, Mask True",
			mask:   &common.RegistrationEntryMask{X509SvidTtl: true},
			update: func(e *common.RegistrationEntry) { e.X509SvidTtl = badEntry.X509SvidTtl },
			err:    errors.New("invalid registration entry: X509SvidTtl is not set")},
		{name: "Update X509 SVID TTL, Bad Data, Mask False",
			mask:   &common.RegistrationEntryMask{X509SvidTtl: false},
			update: func(e *common.RegistrationEntry) { e.X509SvidTtl = badEntry.X509SvidTtl },
			result: func(e *common.RegistrationEntry) {}},
		// JWT SVID TTL FIELD -- This field is validated so we check with good and bad data
		{name: "Update JWT SVID TTL, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{JwtSvidTtl: true},
			update: func(e *common.RegistrationEntry) { e.JwtSvidTtl = newEntry.JwtSvidTtl },
			result: func(e *common.RegistrationEntry) { e.JwtSvidTtl = newEntry.JwtSvidTtl }},
		{name: "Update JWT SVID TTL, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{JwtSvidTtl: false},
			update: func(e *common.RegistrationEntry) { e.JwtSvidTtl = badEntry.JwtSvidTtl },
			result: func(e *common.RegistrationEntry) {}},
		{name: "Update JWT SVID TTL, Bad Data, Mask True",
			mask:   &common.RegistrationEntryMask{JwtSvidTtl: true},
			update: func(e *common.RegistrationEntry) { e.JwtSvidTtl = badEntry.JwtSvidTtl },
			err:    errors.New("invalid registration entry: JwtSvidTtl is not set")},
		{name: "Update JWT SVID TTL, Bad Data, Mask False",
			mask:   &common.RegistrationEntryMask{JwtSvidTtl: false},
			update: func(e *common.RegistrationEntry) { e.JwtSvidTtl = badEntry.JwtSvidTtl },
			result: func(e *common.RegistrationEntry) {}},
		// SELECTORS FIELD -- This field is validated so we check with good and bad data
		{name: "Update Selectors, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{Selectors: true},
			update: func(e *common.RegistrationEntry) { e.Selectors = newEntry.Selectors },
			result: func(e *common.RegistrationEntry) { e.Selectors = newEntry.Selectors }},
		{name: "Update Selectors, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{Selectors: false},
			update: func(e *common.RegistrationEntry) { e.Selectors = badEntry.Selectors },
			result: func(e *common.RegistrationEntry) {}},
		{name: "Update Selectors, Bad Data, Mask True",
			mask:   &common.RegistrationEntryMask{Selectors: true},
			update: func(e *common.RegistrationEntry) { e.Selectors = badEntry.Selectors },
			err:    errors.New("invalid registration entry: missing selector list")},
		{name: "Update Selectors, Bad Data, Mask False",
			mask:   &common.RegistrationEntryMask{Selectors: false},
			update: func(e *common.RegistrationEntry) { e.Selectors = badEntry.Selectors },
			result: func(e *common.RegistrationEntry) {}},
		// FEDERATESWITH FIELD -- This field isn't validated so we just check with good data
		{name: "Update FederatesWith, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{FederatesWith: true},
			update: func(e *common.RegistrationEntry) { e.FederatesWith = newEntry.FederatesWith },
			result: func(e *common.RegistrationEntry) { e.FederatesWith = newEntry.FederatesWith }},
		{name: "Update FederatesWith Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{FederatesWith: false},
			update: func(e *common.RegistrationEntry) { e.FederatesWith = newEntry.FederatesWith },
			result: func(e *common.RegistrationEntry) {}},
		// ADMIN FIELD -- This field isn't validated so we just check with good data
		{name: "Update Admin, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{Admin: true},
			update: func(e *common.RegistrationEntry) { e.Admin = newEntry.Admin },
			result: func(e *common.RegistrationEntry) { e.Admin = newEntry.Admin }},
		{name: "Update Admin, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{Admin: false},
			update: func(e *common.RegistrationEntry) { e.Admin = newEntry.Admin },
			result: func(e *common.RegistrationEntry) {}},

		// STORESVID FIELD -- This field isn't validated so we just check with good data
		{name: "Update StoreSvid, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{StoreSvid: true},
			update: func(e *common.RegistrationEntry) { e.StoreSvid = newEntry.StoreSvid },
			result: func(e *common.RegistrationEntry) { e.StoreSvid = newEntry.StoreSvid }},
		{name: "Update StoreSvid, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{Admin: false},
			update: func(e *common.RegistrationEntry) { e.StoreSvid = newEntry.StoreSvid },
			result: func(e *common.RegistrationEntry) {}},
		{name: "Update StoreSvid, Invalid selectors, Mask True",
			mask: &common.RegistrationEntryMask{StoreSvid: true, Selectors: true},
			update: func(e *common.RegistrationEntry) {
				e.StoreSvid = newEntry.StoreSvid
				e.Selectors = []*common.Selector{
					{Type: "Type1", Value: "Value1"},
					{Type: "Type2", Value: "Value2"},
				}
			},
			err: sqlError.New("invalid registration entry: selector types must be the same when store SVID is enabled"),
		},

		// ENTRYEXPIRY FIELD -- This field isn't validated so we just check with good data
		{name: "Update EntryExpiry, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{EntryExpiry: true},
			update: func(e *common.RegistrationEntry) { e.EntryExpiry = newEntry.EntryExpiry },
			result: func(e *common.RegistrationEntry) { e.EntryExpiry = newEntry.EntryExpiry }},
		{name: "Update EntryExpiry, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{EntryExpiry: false},
			update: func(e *common.RegistrationEntry) { e.EntryExpiry = newEntry.EntryExpiry },
			result: func(e *common.RegistrationEntry) {}},
		// DNSNAMES FIELD -- This field isn't validated so we just check with good data
		{name: "Update DnsNames, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{DnsNames: true},
			update: func(e *common.RegistrationEntry) { e.DnsNames = newEntry.DnsNames },
			result: func(e *common.RegistrationEntry) { e.DnsNames = newEntry.DnsNames }},
		{name: "Update DnsNames, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{DnsNames: false},
			update: func(e *common.RegistrationEntry) { e.DnsNames = newEntry.DnsNames },
			result: func(e *common.RegistrationEntry) {}},
		// DOWNSTREAM FIELD -- This field isn't validated so we just check with good data
		{name: "Update DnsNames, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{Downstream: true},
			update: func(e *common.RegistrationEntry) { e.Downstream = newEntry.Downstream },
			result: func(e *common.RegistrationEntry) { e.Downstream = newEntry.Downstream }},
		{name: "Update DnsNames, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{Downstream: false},
			update: func(e *common.RegistrationEntry) { e.Downstream = newEntry.Downstream },
			result: func(e *common.RegistrationEntry) {}},
		// HINT -- This field isn't validated so we just check with good data
		{name: "Update Hint, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{Hint: true},
			update: func(e *common.RegistrationEntry) { e.Hint = newEntry.Hint },
			result: func(e *common.RegistrationEntry) { e.Hint = newEntry.Hint }},
		{name: "Update Hint, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{Hint: false},
			update: func(e *common.RegistrationEntry) { e.Hint = newEntry.Hint },
			result: func(e *common.RegistrationEntry) {}},
		// This should update all fields
		{name: "Test With Nil Mask",
			mask:   nil,
			update: func(e *common.RegistrationEntry) { proto.Merge(e, oldEntry) },
			result: func(e *common.RegistrationEntry) {}},
	} {
		tt := testcase
		s.Run(tt.name, func() {
			if id != "" {
				s.deleteRegistrationEntry(id)
			}
			registrationEntry := s.createRegistrationEntry(oldEntry)
			id = registrationEntry.EntryId

			updateEntry := &common.RegistrationEntry{}
			tt.update(updateEntry)
			updateEntry.EntryId = id
			updatedRegistrationEntry, err := s.ds.UpdateRegistrationEntry(ctx, updateEntry, tt.mask)

			if tt.err != nil {
				s.Require().ErrorContains(err, tt.err.Error())
				return
			}

			s.Require().NoError(err)
			expectedResult := proto.Clone(oldEntry).(*common.RegistrationEntry)
			tt.result(expectedResult)
			expectedResult.EntryId = id
			expectedResult.RevisionNumber++
			s.assertCreatedAtField(updatedRegistrationEntry, now)
			s.RequireProtoEqual(expectedResult, updatedRegistrationEntry)

			// Fetch and check the results match expectations
			registrationEntry, err = s.ds.FetchRegistrationEntry(ctx, id)
			s.Require().NoError(err)
			s.Require().NotNil(registrationEntry)

			s.assertCreatedAtField(registrationEntry, now)

			s.RequireProtoEqual(expectedResult, registrationEntry)
		})
	}
}

func (s *PluginSuite) TestDeleteRegistrationEntry() {
	// delete non-existing
	_, err := s.ds.DeleteRegistrationEntry(ctx, "badid")
	s.RequireGRPCStatus(err, codes.NotFound, _notFoundErrMsg)

	entry1 := s.createRegistrationEntry(&common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
			{Type: "Type2", Value: "Value2"},
			{Type: "Type3", Value: "Value3"},
		},
		SpiffeId:    "spiffe://example.org/foo",
		ParentId:    "spiffe://example.org/bar",
		X509SvidTtl: 1,
	})

	s.createRegistrationEntry(&common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type3", Value: "Value3"},
			{Type: "Type4", Value: "Value4"},
			{Type: "Type5", Value: "Value5"},
		},
		SpiffeId:    "spiffe://example.org/baz",
		ParentId:    "spiffe://example.org/bat",
		X509SvidTtl: 2,
	})

	// We have two registration entries
	entriesResp, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	s.Require().NoError(err)
	s.Require().Len(entriesResp.Entries, 2)

	// Make sure we deleted the right one
	deletedEntry, err := s.ds.DeleteRegistrationEntry(ctx, entry1.EntryId)
	s.Require().NoError(err)
	s.Require().Equal(entry1, deletedEntry)

	// Make sure we have now only one registration entry
	entriesResp, err = s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	s.Require().NoError(err)
	s.Require().Len(entriesResp.Entries, 1)

	// Delete again must fails with Not Found
	deletedEntry, err = s.ds.DeleteRegistrationEntry(ctx, entry1.EntryId)
	s.Require().EqualError(err, "rpc error: code = NotFound desc = datastore-sql: record not found")
	s.Require().Nil(deletedEntry)
}

func (s *PluginSuite) TestListParentIDEntries() {
	now := time.Now().Unix()
	allEntries := make([]*common.RegistrationEntry, 0)
	s.getTestDataFromJSONFile(filepath.Join("testdata", "entries.json"), &allEntries)
	tests := []struct {
		name                string
		registrationEntries []*common.RegistrationEntry
		parentID            string
		expectedList        []*common.RegistrationEntry
	}{
		{

			name:                "test_parentID_found",
			registrationEntries: allEntries,
			parentID:            "spiffe://parent",
			expectedList:        allEntries[:2],
		},
		{
			name:                "test_parentID_notfound",
			registrationEntries: allEntries,
			parentID:            "spiffe://imnoparent",
			expectedList:        nil,
		},
	}
	for _, test := range tests {
		test := test
		s.T().Run(test.name, func(t *testing.T) {
			ds := s.newPlugin()
			defer ds.Close()
			for _, entry := range test.registrationEntries {
				registrationEntry, err := ds.CreateRegistrationEntry(ctx, entry)
				require.NoError(t, err)
				require.NotNil(t, registrationEntry)
				entry.EntryId = registrationEntry.EntryId
			}
			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				ByParentID: test.parentID,
			})
			require.NoError(t, err)
			s.assertCreatedAtFields(result, now)
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestListSelectorEntries() {
	now := time.Now().Unix()
	allEntries := make([]*common.RegistrationEntry, 0)
	s.getTestDataFromJSONFile(filepath.Join("testdata", "entries.json"), &allEntries)
	tests := []struct {
		name                string
		registrationEntries []*common.RegistrationEntry
		selectors           []*common.Selector
		expectedList        []*common.RegistrationEntry
	}{
		{
			name:                "entries_by_selector_found",
			registrationEntries: allEntries,
			selectors: []*common.Selector{
				{Type: "a", Value: "1"},
				{Type: "b", Value: "2"},
				{Type: "c", Value: "3"},
			},
			expectedList: []*common.RegistrationEntry{allEntries[0]},
		},
		{
			name:                "entries_by_selector_not_found",
			registrationEntries: allEntries,
			selectors: []*common.Selector{
				{Type: "e", Value: "0"},
			},
			expectedList: nil,
		},
	}
	for _, test := range tests {
		test := test
		s.T().Run(test.name, func(t *testing.T) {
			ds := s.newPlugin()
			defer ds.Close()
			for _, entry := range test.registrationEntries {
				registrationEntry, err := ds.CreateRegistrationEntry(ctx, entry)
				require.NoError(t, err)
				require.NotNil(t, registrationEntry)
				entry.EntryId = registrationEntry.EntryId
			}
			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				BySelectors: &datastore.BySelectors{
					Selectors: test.selectors,
					Match:     datastore.Exact,
				},
			})
			require.NoError(t, err)
			s.assertCreatedAtFields(result, now)
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestListEntriesBySelectorSubset() {
	now := time.Now().Unix()
	allEntries := make([]*common.RegistrationEntry, 0)
	s.getTestDataFromJSONFile(filepath.Join("testdata", "entries.json"), &allEntries)
	tests := []struct {
		name                string
		registrationEntries []*common.RegistrationEntry
		selectors           []*common.Selector
		expectedList        []*common.RegistrationEntry
	}{
		{
			name:                "test1",
			registrationEntries: allEntries,
			selectors: []*common.Selector{
				{Type: "a", Value: "1"},
				{Type: "b", Value: "2"},
				{Type: "c", Value: "3"},
			},
			expectedList: []*common.RegistrationEntry{
				allEntries[0],
				allEntries[1],
				allEntries[2],
			},
		},
		{
			name:                "test2",
			registrationEntries: allEntries,
			selectors: []*common.Selector{
				{Type: "d", Value: "4"},
			},
			expectedList: nil,
		},
	}
	for _, test := range tests {
		test := test
		s.T().Run(test.name, func(t *testing.T) {
			ds := s.newPlugin()
			defer ds.Close()
			for _, entry := range test.registrationEntries {
				registrationEntry, err := ds.CreateRegistrationEntry(ctx, entry)
				require.NoError(t, err)
				require.NotNil(t, registrationEntry)
				entry.EntryId = registrationEntry.EntryId
			}
			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				BySelectors: &datastore.BySelectors{
					Selectors: test.selectors,
					Match:     datastore.Subset,
				},
			})
			require.NoError(t, err)
			util.SortRegistrationEntries(test.expectedList)
			util.SortRegistrationEntries(result.Entries)
			s.assertCreatedAtFields(result, now)
			s.RequireProtoListEqual(test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestListSelectorEntriesSuperset() {
	now := time.Now().Unix()
	allEntries := make([]*common.RegistrationEntry, 0)
	s.getTestDataFromJSONFile(filepath.Join("testdata", "entries.json"), &allEntries)
	tests := []struct {
		name                string
		registrationEntries []*common.RegistrationEntry
		selectors           []*common.Selector
		expectedList        []*common.RegistrationEntry
	}{
		{
			name:                "entries_by_selector_found",
			registrationEntries: allEntries,
			selectors: []*common.Selector{
				{Type: "a", Value: "1"},
				{Type: "c", Value: "3"},
			},
			expectedList: []*common.RegistrationEntry{
				allEntries[0],
				allEntries[3],
			},
		},
		{
			name:                "entries_by_selector_not_found",
			registrationEntries: allEntries,
			selectors: []*common.Selector{
				{Type: "e", Value: "0"},
			},
			expectedList: nil,
		},
	}
	for _, test := range tests {
		test := test
		s.T().Run(test.name, func(t *testing.T) {
			ds := s.newPlugin()
			defer ds.Close()
			for _, entry := range test.registrationEntries {
				registrationEntry, err := ds.CreateRegistrationEntry(ctx, entry)
				require.NoError(t, err)
				require.NotNil(t, registrationEntry)
				entry.EntryId = registrationEntry.EntryId
			}
			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				BySelectors: &datastore.BySelectors{
					Selectors: test.selectors,
					Match:     datastore.Superset,
				},
			})
			require.NoError(t, err)
			s.assertCreatedAtFields(result, now)
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestListEntriesBySelectorMatchAny() {
	now := time.Now().Unix()
	allEntries := make([]*common.RegistrationEntry, 0)
	s.getTestDataFromJSONFile(filepath.Join("testdata", "entries.json"), &allEntries)
	tests := []struct {
		name                string
		registrationEntries []*common.RegistrationEntry
		selectors           []*common.Selector
		expectedList        []*common.RegistrationEntry
	}{
		{
			name:                "multiple selectors",
			registrationEntries: allEntries,
			selectors: []*common.Selector{
				{Type: "c", Value: "3"},
				{Type: "d", Value: "4"},
			},
			expectedList: []*common.RegistrationEntry{
				allEntries[0],
				allEntries[2],
				allEntries[3],
				allEntries[4],
			},
		},
		{
			name:                "single selector",
			registrationEntries: allEntries,
			selectors: []*common.Selector{
				{Type: "d", Value: "4"},
			},
			expectedList: []*common.RegistrationEntry{
				allEntries[3],
				allEntries[4],
			},
		},
		{
			name:                "no match",
			registrationEntries: allEntries,
			selectors: []*common.Selector{
				{Type: "e", Value: "5"},
			},
			expectedList: nil,
		},
	}
	for _, test := range tests {
		test := test
		s.T().Run(test.name, func(t *testing.T) {
			ds := s.newPlugin()
			defer ds.Close()
			for _, entry := range test.registrationEntries {
				registrationEntry, err := ds.CreateRegistrationEntry(ctx, entry)
				require.NoError(t, err)
				require.NotNil(t, registrationEntry)
				entry.EntryId = registrationEntry.EntryId
			}
			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				BySelectors: &datastore.BySelectors{
					Selectors: test.selectors,
					Match:     datastore.MatchAny,
				},
			})
			require.NoError(t, err)
			util.SortRegistrationEntries(test.expectedList)
			util.SortRegistrationEntries(result.Entries)
			s.assertCreatedAtFields(result, now)
			s.RequireProtoListEqual(test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestListEntriesByFederatesWithExact() {
	now := time.Now().Unix()
	allEntries := make([]*common.RegistrationEntry, 0)
	s.getTestDataFromJSONFile(filepath.Join("testdata", "entries_federates_with.json"), &allEntries)
	tests := []struct {
		name                string
		registrationEntries []*common.RegistrationEntry
		trustDomains        []string
		expectedList        []*common.RegistrationEntry
	}{
		{
			name:                "multiple selectors",
			registrationEntries: allEntries,
			trustDomains: []string{
				"spiffe://td1.org",
				"spiffe://td2.org",
				"spiffe://td3.org",
			},
			expectedList: []*common.RegistrationEntry{
				allEntries[0],
			},
		},
		{
			name:                "with a subset",
			registrationEntries: allEntries,
			trustDomains: []string{
				"spiffe://td1.org",
				"spiffe://td2.org",
			},
			expectedList: []*common.RegistrationEntry{
				allEntries[1],
			},
		},
		{
			name:                "no match",
			registrationEntries: allEntries,
			trustDomains: []string{
				"spiffe://td1.org",
			},
			expectedList: nil,
		},
	}
	for _, test := range tests {
		test := test
		s.T().Run(test.name, func(t *testing.T) {
			ds := s.newPlugin()
			defer ds.Close()
			createBundles(t, ds, []string{
				"spiffe://td1.org",
				"spiffe://td2.org",
				"spiffe://td3.org",
				"spiffe://td4.org",
			})

			for _, entry := range test.registrationEntries {
				registrationEntry, err := ds.CreateRegistrationEntry(ctx, entry)
				require.NoError(t, err)
				require.NotNil(t, registrationEntry)
				entry.EntryId = registrationEntry.EntryId
			}
			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				ByFederatesWith: &datastore.ByFederatesWith{
					TrustDomains: test.trustDomains,
					Match:        datastore.Exact,
				},
			})
			require.NoError(t, err)
			util.SortRegistrationEntries(test.expectedList)
			util.SortRegistrationEntries(result.Entries)

			s.assertCreatedAtFields(result, now)

			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestListEntriesByFederatesWithSubset() {
	now := time.Now().Unix()
	allEntries := make([]*common.RegistrationEntry, 0)
	s.getTestDataFromJSONFile(filepath.Join("testdata", "entries_federates_with.json"), &allEntries)
	tests := []struct {
		name                string
		registrationEntries []*common.RegistrationEntry
		trustDomains        []string
		expectedList        []*common.RegistrationEntry
	}{
		{
			name:                "multiple selectors",
			registrationEntries: allEntries,
			trustDomains: []string{
				"spiffe://td1.org",
				"spiffe://td2.org",
				"spiffe://td3.org",
			},
			expectedList: []*common.RegistrationEntry{
				allEntries[0],
				allEntries[1],
				allEntries[2],
			},
		},
		{
			name:                "no match",
			registrationEntries: allEntries,
			trustDomains: []string{
				"spiffe://td4.org",
			},
			expectedList: nil,
		},
	}
	for _, test := range tests {
		test := test
		s.T().Run(test.name, func(t *testing.T) {
			ds := s.newPlugin()
			defer ds.Close()
			createBundles(t, ds, []string{
				"spiffe://td1.org",
				"spiffe://td2.org",
				"spiffe://td3.org",
				"spiffe://td4.org",
			})

			for _, entry := range test.registrationEntries {
				registrationEntry, err := ds.CreateRegistrationEntry(ctx, entry)
				require.NoError(t, err)
				require.NotNil(t, registrationEntry)
				entry.EntryId = registrationEntry.EntryId
			}
			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				ByFederatesWith: &datastore.ByFederatesWith{
					TrustDomains: test.trustDomains,
					Match:        datastore.Subset,
				},
			})
			require.NoError(t, err)
			util.SortRegistrationEntries(test.expectedList)
			util.SortRegistrationEntries(result.Entries)
			s.assertCreatedAtFields(result, now)
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestListEntriesByFederatesWithMatchAny() {
	now := time.Now().Unix()
	allEntries := make([]*common.RegistrationEntry, 0)
	s.getTestDataFromJSONFile(filepath.Join("testdata", "entries_federates_with.json"), &allEntries)
	tests := []struct {
		name                string
		registrationEntries []*common.RegistrationEntry
		trustDomains        []string
		expectedList        []*common.RegistrationEntry
	}{
		{
			name:                "multiple selectors",
			registrationEntries: allEntries,
			trustDomains: []string{
				"spiffe://td3.org",
				"spiffe://td4.org",
			},
			expectedList: []*common.RegistrationEntry{
				allEntries[0],
				allEntries[2],
				allEntries[3],
				allEntries[4],
			},
		},
		{
			name:                "single selector",
			registrationEntries: allEntries,
			trustDomains:        []string{"spiffe://td4.org"},
			expectedList: []*common.RegistrationEntry{
				allEntries[3],
				allEntries[4],
			},
		},
		{
			name:                "no match",
			registrationEntries: allEntries,
			trustDomains:        []string{"spiffe://td5.org"},
			expectedList:        nil,
		},
	}
	for _, test := range tests {
		test := test
		s.T().Run(test.name, func(t *testing.T) {
			ds := s.newPlugin()
			defer ds.Close()
			createBundles(t, ds, []string{
				"spiffe://td1.org",
				"spiffe://td2.org",
				"spiffe://td3.org",
				"spiffe://td4.org",
			})

			for _, entry := range test.registrationEntries {
				registrationEntry, err := ds.CreateRegistrationEntry(ctx, entry)
				require.NoError(t, err)
				require.NotNil(t, registrationEntry)
				entry.EntryId = registrationEntry.EntryId
			}
			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				ByFederatesWith: &datastore.ByFederatesWith{
					TrustDomains: test.trustDomains,
					Match:        datastore.MatchAny,
				},
			})
			require.NoError(t, err)
			util.SortRegistrationEntries(test.expectedList)
			util.SortRegistrationEntries(result.Entries)
			s.assertCreatedAtFields(result, now)
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestListEntriesByFederatesWithSuperset() {
	now := time.Now().Unix()
	allEntries := make([]*common.RegistrationEntry, 0)
	s.getTestDataFromJSONFile(filepath.Join("testdata", "entries_federates_with.json"), &allEntries)
	tests := []struct {
		name                string
		registrationEntries []*common.RegistrationEntry
		trustDomains        []string
		expectedList        []*common.RegistrationEntry
	}{
		{
			name:                "multiple selectors",
			registrationEntries: allEntries,
			trustDomains: []string{
				"spiffe://td1.org",
				"spiffe://td3.org",
			},
			expectedList: []*common.RegistrationEntry{
				allEntries[0],
				allEntries[3],
			},
		},
		{
			name:                "single selector",
			registrationEntries: allEntries,
			trustDomains:        []string{"spiffe://td3.org"},
			expectedList: []*common.RegistrationEntry{
				allEntries[0],
				allEntries[2],
				allEntries[3],
			},
		},
		{
			name:                "no match",
			registrationEntries: allEntries,
			trustDomains:        []string{"spiffe://td5.org"},
			expectedList:        nil,
		},
	}
	for _, test := range tests {
		test := test
		s.T().Run(test.name, func(t *testing.T) {
			ds := s.newPlugin()
			defer ds.Close()
			createBundles(t, ds, []string{
				"spiffe://td1.org",
				"spiffe://td2.org",
				"spiffe://td3.org",
				"spiffe://td4.org",
			})

			for _, entry := range test.registrationEntries {
				registrationEntry, err := ds.CreateRegistrationEntry(ctx, entry)
				require.NoError(t, err)
				require.NotNil(t, registrationEntry)
				entry.EntryId = registrationEntry.EntryId
			}
			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				ByFederatesWith: &datastore.ByFederatesWith{
					TrustDomains: test.trustDomains,
					Match:        datastore.Superset,
				},
			})
			require.NoError(t, err)
			util.SortRegistrationEntries(test.expectedList)
			util.SortRegistrationEntries(result.Entries)
			s.assertCreatedAtFields(result, now)
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestRegistrationEntriesFederatesWithAgainstMissingBundle() {
	// cannot federate with a trust bundle that does not exist
	_, err := s.ds.CreateRegistrationEntry(ctx, makeFederatedRegistrationEntry())
	s.RequireErrorContains(err, `unable to find federated bundle "spiffe://otherdomain.org"`)
}

func (s *PluginSuite) TestRegistrationEntriesFederatesWithSuccess() {
	// create two bundles but only federate with one. having a second bundle
	// has the side effect of asserting that only the code only associates
	// the entry with the exact bundle referenced during creation.
	s.createBundle("spiffe://otherdomain.org")
	s.createBundle("spiffe://otherdomain2.org")

	expected := s.createRegistrationEntry(makeFederatedRegistrationEntry())
	// fetch the entry and make sure the federated trust ids come back
	actual := s.fetchRegistrationEntry(expected.EntryId)
	s.RequireProtoEqual(expected, actual)
}

func (s *PluginSuite) TestDeleteBundleRestrictedByRegistrationEntries() {
	// create the bundle and associated entry
	s.createBundle("spiffe://otherdomain.org")
	s.createRegistrationEntry(makeFederatedRegistrationEntry())

	// delete the bundle in RESTRICTED mode
	err := s.ds.DeleteBundle(context.Background(), "spiffe://otherdomain.org", datastore.Restrict)
	s.RequireErrorContains(err, "datastore-sql: cannot delete bundle; federated with 1 registration entries")
}

func (s *PluginSuite) TestDeleteBundleDeleteRegistrationEntries() {
	// create an unrelated registration entry to make sure the delete
	// operation only deletes associated registration entries.
	unrelated := s.createRegistrationEntry(&common.RegistrationEntry{
		SpiffeId:  "spiffe://example.org/foo",
		Selectors: []*common.Selector{{Type: "TYPE", Value: "VALUE"}},
	})

	// create the bundle and associated entry
	s.createBundle("spiffe://otherdomain.org")
	entry := s.createRegistrationEntry(makeFederatedRegistrationEntry())

	// delete the bundle in Delete mode
	err := s.ds.DeleteBundle(context.Background(), "spiffe://otherdomain.org", datastore.Delete)
	s.Require().NoError(err)

	// verify that the registration entry has been deleted
	registrationEntry, err := s.ds.FetchRegistrationEntry(context.Background(), entry.EntryId)
	s.Require().NoError(err)
	s.Require().Nil(registrationEntry)

	// make sure the unrelated entry still exists
	s.fetchRegistrationEntry(unrelated.EntryId)
}

func (s *PluginSuite) TestDeleteBundleDissociateRegistrationEntries() {
	// create the bundle and associated entry
	s.createBundle("spiffe://otherdomain.org")
	entry := s.createRegistrationEntry(makeFederatedRegistrationEntry())

	// delete the bundle in DISSOCIATE mode
	err := s.ds.DeleteBundle(context.Background(), "spiffe://otherdomain.org", datastore.Dissociate)
	s.Require().NoError(err)

	// make sure the entry still exists, albeit without an associated bundle
	entry = s.fetchRegistrationEntry(entry.EntryId)
	s.Require().Empty(entry.FederatesWith)
}

func (s *PluginSuite) TestCreateJoinToken() {
	req := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: time.Now().Truncate(time.Second),
	}
	err := s.ds.CreateJoinToken(ctx, req)
	s.Require().NoError(err)

	// Make sure we can't re-register
	err = s.ds.CreateJoinToken(ctx, req)
	s.NotNil(err)
}

func (s *PluginSuite) TestCreateAndFetchJoinToken() {
	now := time.Now().Truncate(time.Second)
	joinToken := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: now,
	}

	err := s.ds.CreateJoinToken(ctx, joinToken)
	s.Require().NoError(err)

	res, err := s.ds.FetchJoinToken(ctx, joinToken.Token)
	s.Require().NoError(err)
	s.Equal("foobar", res.Token)
	s.Equal(now, res.Expiry)
}

func (s *PluginSuite) TestDeleteJoinToken() {
	now := time.Now().Truncate(time.Second)
	joinToken1 := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: now,
	}

	err := s.ds.CreateJoinToken(ctx, joinToken1)
	s.Require().NoError(err)

	joinToken2 := &datastore.JoinToken{
		Token:  "batbaz",
		Expiry: now,
	}

	err = s.ds.CreateJoinToken(ctx, joinToken2)
	s.Require().NoError(err)

	err = s.ds.DeleteJoinToken(ctx, joinToken1.Token)
	s.Require().NoError(err)

	// Should not be able to fetch after delete
	resp, err := s.ds.FetchJoinToken(ctx, joinToken1.Token)
	s.Require().NoError(err)
	s.Nil(resp)

	// Second token should still be present
	resp, err = s.ds.FetchJoinToken(ctx, joinToken2.Token)
	s.Require().NoError(err)
	s.Equal(joinToken2, resp)
}

func (s *PluginSuite) TestPruneJoinTokens() {
	now := time.Now().Truncate(time.Second)
	joinToken := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: now,
	}

	err := s.ds.CreateJoinToken(ctx, joinToken)
	s.Require().NoError(err)

	// Ensure we don't prune valid tokens, wind clock back 10s
	err = s.ds.PruneJoinTokens(ctx, now.Add(-time.Second*10))
	s.Require().NoError(err)

	resp, err := s.ds.FetchJoinToken(ctx, joinToken.Token)
	s.Require().NoError(err)
	s.Equal("foobar", resp.Token)

	// Ensure we don't prune on the exact ExpiresBefore
	err = s.ds.PruneJoinTokens(ctx, now)
	s.Require().NoError(err)

	resp, err = s.ds.FetchJoinToken(ctx, joinToken.Token)
	s.Require().NoError(err)
	s.Require().NotNil(resp, "token was unexpectedly pruned")
	s.Equal("foobar", resp.Token)

	// Ensure we prune old tokens
	err = s.ds.PruneJoinTokens(ctx, now.Add(time.Second*10))
	s.Require().NoError(err)

	resp, err = s.ds.FetchJoinToken(ctx, joinToken.Token)
	s.Require().NoError(err)
	s.Nil(resp)
}

func (s *PluginSuite) TestDeleteFederationRelationship() {
	testCases := []struct {
		name        string
		trustDomain spiffeid.TrustDomain
		expErr      string
		setupFn     func()
	}{
		{
			name:        "deleting an existent federation relationship succeeds",
			trustDomain: spiffeid.RequireTrustDomainFromString("federated-td-web.org"),
			setupFn: func() {
				_, err := s.ds.CreateFederationRelationship(ctx, &datastore.FederationRelationship{
					TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-web.org"),
					BundleEndpointURL:     requireURLFromString(s.T(), "federated-td-web.org/bundleendpoint"),
					BundleEndpointProfile: datastore.BundleEndpointWeb,
				})
				s.Require().NoError(err)
			},
		},
		{
			name:        "deleting an unexistent federation relationship returns not found",
			trustDomain: spiffeid.RequireTrustDomainFromString("non-existent-td.org"),
			expErr:      "rpc error: code = NotFound desc = datastore-sql: record not found",
		},
		{
			name:   "deleting a federation relationship using an empty trust domain fails nicely",
			expErr: "rpc error: code = InvalidArgument desc = trust domain is required",
		},
	}

	for _, tt := range testCases {
		s.T().Run(tt.name, func(t *testing.T) {
			if tt.setupFn != nil {
				tt.setupFn()
			}

			err := s.ds.DeleteFederationRelationship(ctx, tt.trustDomain)
			if tt.expErr != "" {
				s.Require().EqualError(err, tt.expErr)
				return
			}
			s.Require().NoError(err)

			fr, err := s.ds.FetchFederationRelationship(ctx, tt.trustDomain)
			s.Require().NoError(err)
			s.Require().Nil(fr)
		})
	}
}

func (s *PluginSuite) TestFetchFederationRelationship() {
	testCases := []struct {
		name        string
		trustDomain spiffeid.TrustDomain
		expErr      string
		expFR       *datastore.FederationRelationship
	}{
		{
			name:        "fetching an existent federation relationship succeeds for web profile",
			trustDomain: spiffeid.RequireTrustDomainFromString("federated-td-web.org"),
			expFR: func() *datastore.FederationRelationship {
				fr, err := s.ds.CreateFederationRelationship(ctx, &datastore.FederationRelationship{
					TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-web.org"),
					BundleEndpointURL:     requireURLFromString(s.T(), "federated-td-web.org/bundleendpoint"),
					BundleEndpointProfile: datastore.BundleEndpointWeb,
				})
				s.Require().NoError(err)
				return fr
			}(),
		},
		{
			name:        "fetching an existent federation relationship succeeds for spiffe profile",
			trustDomain: spiffeid.RequireTrustDomainFromString("federated-td-spiffe.org"),
			expFR: func() *datastore.FederationRelationship {
				trustDomainBundle := s.createBundle("spiffe://federated-td-spiffe.org")
				fr, err := s.ds.CreateFederationRelationship(ctx, &datastore.FederationRelationship{
					TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-spiffe.org"),
					BundleEndpointURL:     requireURLFromString(s.T(), "federated-td-spiffe.org/bundleendpoint"),
					BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
					EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://federated-td-spiffe.org/federated-server"),
					TrustDomainBundle:     trustDomainBundle,
				})
				s.Require().NoError(err)
				return fr
			}(),
		},
		{
			name:        "fetching an existent federation relationship succeeds for profile without bundle",
			trustDomain: spiffeid.RequireTrustDomainFromString("domain.test"),
			expFR: func() *datastore.FederationRelationship {
				fr, err := s.ds.CreateFederationRelationship(ctx, &datastore.FederationRelationship{
					TrustDomain:           spiffeid.RequireTrustDomainFromString("domain.test"),
					BundleEndpointURL:     requireURLFromString(s.T(), "https://domain.test/bundleendpoint"),
					BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
					EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://domain.test/federated-server"),
				})
				s.Require().NoError(err)
				return fr
			}(),
		},
		{
			name:        "fetching a non-existent federation relationship returns nil",
			trustDomain: spiffeid.RequireTrustDomainFromString("non-existent-td.org"),
		},
		{
			name:   "fetching en empty trust domain fails nicely",
			expErr: "rpc error: code = InvalidArgument desc = trust domain is required",
		},
		{
			name:        "fetching a federation relationship with corrupted bundle endpoint URL fails nicely",
			expErr:      "rpc error: code = Unknown desc = unable to parse URL: parse \"not-valid-endpoint-url%\": invalid URL escape \"%\"",
			trustDomain: spiffeid.RequireTrustDomainFromString("corrupted-bundle-endpoint-url.org"),
			expFR: func() *datastore.FederationRelationship { //nolint // returns nil on purpose
				model := FederatedTrustDomain{
					TrustDomain:           "corrupted-bundle-endpoint-url.org",
					BundleEndpointURL:     "not-valid-endpoint-url%",
					BundleEndpointProfile: string(datastore.BundleEndpointWeb),
				}
				s.Require().NoError(s.ds.db.Create(&model).Error)
				return nil
			}(),
		},
		{
			name:        "fetching a federation relationship with corrupted bundle endpoint SPIFFE ID fails nicely",
			expErr:      "rpc error: code = Unknown desc = unable to parse bundle endpoint SPIFFE ID: scheme is missing or invalid",
			trustDomain: spiffeid.RequireTrustDomainFromString("corrupted-bundle-endpoint-id.org"),
			expFR: func() *datastore.FederationRelationship { //nolint // returns nil on purpose
				model := FederatedTrustDomain{
					TrustDomain:           "corrupted-bundle-endpoint-id.org",
					BundleEndpointURL:     "corrupted-bundle-endpoint-id.org/bundleendpoint",
					BundleEndpointProfile: string(datastore.BundleEndpointSPIFFE),
					EndpointSPIFFEID:      "invalid-id",
				}
				s.Require().NoError(s.ds.db.Create(&model).Error)
				return nil
			}(),
		},
		{
			name:        "fetching a federation relationship with corrupted type fails nicely",
			expErr:      "rpc error: code = Unknown desc = unknown bundle endpoint profile type: \"other\"",
			trustDomain: spiffeid.RequireTrustDomainFromString("corrupted-endpoint-profile.org"),
			expFR: func() *datastore.FederationRelationship { //nolint // returns nil on purpose
				model := FederatedTrustDomain{
					TrustDomain:           "corrupted-endpoint-profile.org",
					BundleEndpointURL:     "corrupted-endpoint-profile.org/bundleendpoint",
					BundleEndpointProfile: "other",
				}
				s.Require().NoError(s.ds.db.Create(&model).Error)
				return nil
			}(),
		},
	}

	for _, tt := range testCases {
		s.T().Run(tt.name, func(t *testing.T) {
			fr, err := s.ds.FetchFederationRelationship(ctx, tt.trustDomain)
			if tt.expErr != "" {
				require.EqualError(t, err, tt.expErr)
				require.Nil(t, fr)
				return
			}

			require.NoError(t, err)
			assertFederationRelationship(t, tt.expFR, fr)
		})
	}
}

func (s *PluginSuite) TestCreateFederationRelationship() {
	s.createBundle("spiffe://federated-td-spiffe.org")
	s.createBundle("spiffe://federated-td-spiffe-with-bundle.org")

	testCases := []struct {
		name       string
		expectCode codes.Code
		expectMsg  string
		fr         *datastore.FederationRelationship
	}{
		{
			name: "creating a new federation relationship succeeds for web profile",
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-web.org"),
				BundleEndpointURL:     requireURLFromString(s.T(), "federated-td-web.org/bundleendpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
		},
		{
			name: "creating a new federation relationship succeeds for spiffe profile",
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-spiffe.org"),
				BundleEndpointURL:     requireURLFromString(s.T(), "federated-td-spiffe.org/bundleendpoint"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://federated-td-spiffe.org/federated-server"),
			},
		},
		{
			name: "creating a new federation relationship succeeds for web profile and new bundle",
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-web-with-bundle.org"),
				BundleEndpointURL:     requireURLFromString(s.T(), "federated-td-web-with-bundle.org/bundleendpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
				TrustDomainBundle: func() *common.Bundle {
					newBundle := bundleutil.BundleProtoFromRootCA("spiffe://federated-td-web-with-bundle.org", s.cert)
					newBundle.RefreshHint = int64(10) // modify bundle to assert it was updated
					return newBundle
				}(),
			},
		},
		{
			name: "creating a new federation relationship succeeds for spiffe profile and new bundle",
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-spiffe-with-bundle.org"),
				BundleEndpointURL:     requireURLFromString(s.T(), "federated-td-spiffe-with-bundle.org/bundleendpoint"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://federated-td-spiffe-with-bundle.org/federated-server"),
				TrustDomainBundle: func() *common.Bundle {
					newBundle := bundleutil.BundleProtoFromRootCA("spiffe://federated-td-spiffe-with-bundle.org", s.cert)
					newBundle.RefreshHint = int64(10) // modify bundle to assert it was updated
					return newBundle
				}(),
			},
		},
		{
			name:       "creating a new nil federation relationship fails nicely ",
			expectCode: codes.InvalidArgument,
			expectMsg:  "federation relationship is nil",
		},
		{
			name:       "creating a new federation relationship without trust domain fails nicely ",
			expectCode: codes.InvalidArgument,
			expectMsg:  "trust domain is required",
			fr: &datastore.FederationRelationship{
				BundleEndpointURL:     requireURLFromString(s.T(), "federated-td-web.org/bundleendpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
		},
		{
			name:       "creating a new federation relationship without bundle endpoint URL fails nicely",
			expectCode: codes.InvalidArgument,
			expectMsg:  "bundle endpoint URL is required",
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-spiffe.org"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://federated-td-spiffe.org/federated-server"),
			},
		},
		{
			name:       "creating a new SPIFFE federation relationship without bundle endpoint SPIFFE ID fails nicely",
			expectCode: codes.InvalidArgument,
			expectMsg:  "bundle endpoint SPIFFE ID is required",
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-spiffe.org"),
				BundleEndpointURL:     requireURLFromString(s.T(), "federated-td-spiffe.org/bundleendpoint"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
			},
		},
		{
			name:       "creating a new SPIFFE federation relationship without initial bundle pass",
			expectCode: codes.OK,
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("no-initial-bundle.org"),
				BundleEndpointURL:     requireURLFromString(s.T(), "no-initial-bundle.org/bundleendpoint"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://no-initial-bundle.org/federated-server"),
			},
		},
		{
			name:       "creating a new federation relationship of unknown type fails nicely",
			expectCode: codes.InvalidArgument,
			expectMsg:  "unknown bundle endpoint profile type: \"wrong-type\"",
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("no-initial-bundle.org"),
				BundleEndpointURL:     requireURLFromString(s.T(), "no-initial-bundle.org/bundleendpoint"),
				BundleEndpointProfile: "wrong-type",
			},
		},
	}

	for _, tt := range testCases {
		s.T().Run(tt.name, func(t *testing.T) {
			fr, err := s.ds.CreateFederationRelationship(ctx, tt.fr)
			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			if tt.expectCode != codes.OK {
				require.Nil(t, fr)
				return
			}
			// TODO: when FetchFederationRelationship is implemented, assert if entry was created

			switch fr.BundleEndpointProfile {
			case datastore.BundleEndpointWeb:
			case datastore.BundleEndpointSPIFFE:
			default:
				require.FailNowf(t, "unexpected bundle endpoint profile type: %q", string(fr.BundleEndpointProfile))
			}

			if fr.TrustDomainBundle != nil {
				// Assert bundle is updated
				bundle, err := s.ds.FetchBundle(ctx, fr.TrustDomain.IDString())
				require.NoError(t, err)
				spiretest.RequireProtoEqual(t, bundle, fr.TrustDomainBundle)
			}
		})
	}
}

func (s *PluginSuite) TestListFederationRelationships() {
	fr1 := &datastore.FederationRelationship{
		TrustDomain:           spiffeid.RequireTrustDomainFromString("spiffe://example-1.org"),
		BundleEndpointURL:     requireURLFromString(s.T(), "https://example-1-web.org/bundleendpoint"),
		BundleEndpointProfile: datastore.BundleEndpointWeb,
	}
	_, err := s.ds.CreateFederationRelationship(ctx, fr1)
	s.Require().NoError(err)

	trustDomainBundle := s.createBundle("spiffe://example-2.org")
	fr2 := &datastore.FederationRelationship{
		TrustDomain:           spiffeid.RequireTrustDomainFromString("spiffe://example-2.org"),
		BundleEndpointURL:     requireURLFromString(s.T(), "https://example-2-web.org/bundleendpoint"),
		BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
		EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://example-2.org/test"),
		TrustDomainBundle:     trustDomainBundle,
	}
	_, err = s.ds.CreateFederationRelationship(ctx, fr2)
	s.Require().NoError(err)

	fr3 := &datastore.FederationRelationship{
		TrustDomain:           spiffeid.RequireTrustDomainFromString("spiffe://example-3.org"),
		BundleEndpointURL:     requireURLFromString(s.T(), "https://example-3-web.org/bundleendpoint"),
		BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
		EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://example-2.org/test"),
	}
	_, err = s.ds.CreateFederationRelationship(ctx, fr3)
	s.Require().NoError(err)

	fr4 := &datastore.FederationRelationship{
		TrustDomain:           spiffeid.RequireTrustDomainFromString("spiffe://example-4.org"),
		BundleEndpointURL:     requireURLFromString(s.T(), "https://example-4-web.org/bundleendpoint"),
		BundleEndpointProfile: datastore.BundleEndpointWeb,
	}
	_, err = s.ds.CreateFederationRelationship(ctx, fr4)
	s.Require().NoError(err)

	tests := []struct {
		name               string
		pagination         *datastore.Pagination
		expectedList       []*datastore.FederationRelationship
		expectedPagination *datastore.Pagination
		expectedErr        string
	}{
		{
			name:         "no pagination",
			expectedList: []*datastore.FederationRelationship{fr1, fr2, fr3, fr4},
		},
		{
			name: "page size bigger than items",
			pagination: &datastore.Pagination{
				PageSize: 5,
			},
			expectedList: []*datastore.FederationRelationship{fr1, fr2, fr3, fr4},
			expectedPagination: &datastore.Pagination{
				Token:    "4",
				PageSize: 5,
			},
		},
		{
			name: "pagination page size is zero",
			pagination: &datastore.Pagination{
				PageSize: 0,
			},
			expectedErr: "rpc error: code = InvalidArgument desc = cannot paginate with pagesize = 0",
		},
		{
			name: "bundles first page",
			pagination: &datastore.Pagination{
				Token:    "0",
				PageSize: 2,
			},
			expectedList: []*datastore.FederationRelationship{fr1, fr2},
			expectedPagination: &datastore.Pagination{Token: "2",
				PageSize: 2,
			},
		},
		{
			name: "federation relationships second page",
			pagination: &datastore.Pagination{
				Token:    "2",
				PageSize: 2,
			},
			expectedList: []*datastore.FederationRelationship{fr3, fr4},
			expectedPagination: &datastore.Pagination{
				Token:    "4",
				PageSize: 2,
			},
		},
		{
			name:         "federation relationships third page",
			expectedList: []*datastore.FederationRelationship{},
			pagination: &datastore.Pagination{
				Token:    "4",
				PageSize: 2,
			},
			expectedPagination: &datastore.Pagination{
				Token:    "",
				PageSize: 2,
			},
		},
		{
			name:         "invalid token",
			expectedList: []*datastore.FederationRelationship{},
			expectedErr:  "rpc error: code = InvalidArgument desc = could not parse token 'invalid token'",
			pagination: &datastore.Pagination{
				Token:    "invalid token",
				PageSize: 2,
			},
			expectedPagination: &datastore.Pagination{
				PageSize: 2,
			},
		},
	}
	for _, test := range tests {
		test := test
		s.T().Run(test.name, func(t *testing.T) {
			resp, err := s.ds.ListFederationRelationships(ctx, &datastore.ListFederationRelationshipsRequest{
				Pagination: test.pagination,
			})
			if test.expectedErr != "" {
				require.EqualError(t, err, test.expectedErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)

			require.Len(t, resp.FederationRelationships, len(test.expectedList))
			for i, each := range resp.FederationRelationships {
				assertFederationRelationship(t, test.expectedList[i], each)
			}

			require.Equal(t, test.expectedPagination, resp.Pagination)
		})
	}
}

func (s *PluginSuite) TestUpdateFederationRelationship() {
	s.createBundle("spiffe://td-with-bundle.org")

	testCases := []struct {
		name      string
		initialFR *datastore.FederationRelationship
		fr        *datastore.FederationRelationship
		mask      *types.FederationRelationshipMask
		expFR     *datastore.FederationRelationship
		expErr    string
	}{
		{
			name: "updating bundle endpoint URL succeeds",
			initialFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointURL:     requireURLFromString(s.T(), "td.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
			fr: &datastore.FederationRelationship{
				TrustDomain:       spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointURL: requireURLFromString(s.T(), "td.org/other-bundle-endpoint"),
			},
			mask: &types.FederationRelationshipMask{BundleEndpointUrl: true},
			expFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointURL:     requireURLFromString(s.T(), "td.org/other-bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
		},
		{
			name: "updating bundle endpoint profile with pre-existent bundle and no input bundle succeeds",
			initialFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-with-bundle.org"),
				BundleEndpointURL:     requireURLFromString(s.T(), "td-with-bundle.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-with-bundle.org"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td-with-bundle.org/federated-server"),
			},
			mask: &types.FederationRelationshipMask{BundleEndpointProfile: true},
			expFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-with-bundle.org"),
				BundleEndpointURL:     requireURLFromString(s.T(), "td-with-bundle.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td-with-bundle.org/federated-server"),
				TrustDomainBundle:     bundleutil.BundleProtoFromRootCA("spiffe://td-with-bundle.org", s.cert),
			},
		},
		{
			name: "updating bundle endpoint profile with pre-existent bundle and input bundle succeeds",
			initialFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-with-bundle.org"),
				BundleEndpointURL:     requireURLFromString(s.T(), "td-with-bundle.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-with-bundle.org"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td-with-bundle.org/federated-server"),
				TrustDomainBundle: func() *common.Bundle {
					newBundle := bundleutil.BundleProtoFromRootCA("spiffe://td-with-bundle.org", s.cert)
					newBundle.RefreshHint = int64(10) // modify bundle to assert it was updated
					return newBundle
				}(),
			},
			mask: &types.FederationRelationshipMask{BundleEndpointProfile: true},
			expFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-with-bundle.org"),
				BundleEndpointURL:     requireURLFromString(s.T(), "td-with-bundle.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td-with-bundle.org/federated-server"),
				TrustDomainBundle: func() *common.Bundle {
					newBundle := bundleutil.BundleProtoFromRootCA("spiffe://td-with-bundle.org", s.cert)
					newBundle.RefreshHint = int64(10)
					return newBundle
				}(),
			},
		},
		{
			name: "updating bundle endpoint profile to SPIFFE without pre-existent bundle succeeds",
			initialFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-without-bundle.org"),
				BundleEndpointURL:     requireURLFromString(s.T(), "td-without-bundle.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-without-bundle.org"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td-without-bundle.org/federated-server"),
				TrustDomainBundle:     bundleutil.BundleProtoFromRootCA("spiffe://td-without-bundle.org", s.cert),
			},
			mask: &types.FederationRelationshipMask{BundleEndpointProfile: true},
			expFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-without-bundle.org"),
				BundleEndpointURL:     requireURLFromString(s.T(), "td-without-bundle.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td-without-bundle.org/federated-server"),
				TrustDomainBundle:     bundleutil.BundleProtoFromRootCA("spiffe://td-without-bundle.org", s.cert),
			},
		},
		{
			name: "updating bundle endpoint profile to without pre-existent bundle and no input bundle pass",
			initialFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointURL:     requireURLFromString(s.T(), "td.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td.org/federated-server"),
			},
			expFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td.org/federated-server"),
				BundleEndpointURL:     requireURLFromString(s.T(), "td.org/bundle-endpoint"),
			},
			mask: &types.FederationRelationshipMask{BundleEndpointProfile: true},
		},
		{
			name: "updating federation relationship for non-existent trust domain fails nicely",
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("non-existent-td.org"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td.org/federated-server"),
			},
			mask:   &types.FederationRelationshipMask{BundleEndpointProfile: true},
			expErr: "rpc error: code = NotFound desc = unable to fetch federation relationship: record not found",
		},
		{
			name:   "updatinga nil federation relationship fails nicely ",
			expErr: "rpc error: code = InvalidArgument desc = federation relationship is nil",
		},
		{
			name:   "updating a federation relationship without trust domain fails nicely ",
			expErr: "rpc error: code = InvalidArgument desc = trust domain is required",
			fr:     &datastore.FederationRelationship{},
		},
		{
			name:   "updating a federation relationship without bundle endpoint URL fails nicely",
			expErr: "rpc error: code = InvalidArgument desc = bundle endpoint URL is required",
			mask:   protoutil.AllTrueFederationRelationshipMask,
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td.org/federated-server"),
			},
		},
		{
			name:   "updating a federation relationship of unknown type fails nicely",
			expErr: "rpc error: code = InvalidArgument desc = unknown bundle endpoint profile type: \"wrong-type\"",
			mask:   protoutil.AllTrueFederationRelationshipMask,
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointURL:     requireURLFromString(s.T(), "td.org/bundle-endpoint"),
				BundleEndpointProfile: "wrong-type",
			},
		},
	}

	for _, tt := range testCases {
		s.T().Run(tt.name, func(t *testing.T) {
			if tt.initialFR != nil {
				_, err := s.ds.CreateFederationRelationship(ctx, tt.initialFR)
				s.Require().NoError(err)
				defer func() { s.Require().NoError(s.ds.DeleteFederationRelationship(ctx, tt.initialFR.TrustDomain)) }()
			}

			updatedFR, err := s.ds.UpdateFederationRelationship(ctx, tt.fr, tt.mask)
			if tt.expErr != "" {
				s.Require().EqualError(err, tt.expErr)
				s.Require().Nil(updatedFR)
				return
			}
			s.Require().NoError(err)
			s.Require().NotNil(updatedFR)

			switch tt.expFR.BundleEndpointProfile {
			case datastore.BundleEndpointWeb:
			case datastore.BundleEndpointSPIFFE:
				// Assert bundle is updated
				bundle, err := s.ds.FetchBundle(ctx, tt.expFR.TrustDomain.IDString())
				s.Require().NoError(err)
				s.RequireProtoEqual(bundle, updatedFR.TrustDomainBundle)

				// Now that bundles were asserted, set them to nil to be able to compare other fields using Require().Equal
				tt.expFR.TrustDomainBundle = nil
				updatedFR.TrustDomainBundle = nil
			default:
				s.Require().FailNowf("unexpected bundle endpoint profile type: %q", string(tt.expFR.BundleEndpointProfile))
			}

			s.Require().Equal(tt.expFR, updatedFR)
		})
	}
}

func (s *PluginSuite) TestCleanStaleNodeResolverEntries() {
	deletedNodeSPIFFEID := "thisNodeDoesNotExist"
	existentNode := &common.AttestedNode{
		SpiffeId:            "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}

	selectors := []*common.Selector{
		{Type: "TYPE1", Value: "VALUE1"},
		{Type: "TYPE2", Value: "VALUE2"},
		{Type: "TYPE3", Value: "VALUE3"},
		{Type: "TYPE4", Value: "VALUE4"},
	}
	_, err := s.ds.CreateAttestedNode(ctx, existentNode)
	require.NoError(s.T(), err)
	err = s.ds.SetNodeSelectors(ctx, existentNode.SpiffeId, selectors)
	require.NoError(s.T(), err)
	nodeSelectors, err := s.ds.GetNodeSelectors(ctx, existentNode.SpiffeId, datastore.RequireCurrent)
	s.Require().NoError(err)
	s.Equal(selectors, nodeSelectors)

	err = s.ds.SetNodeSelectors(ctx, deletedNodeSPIFFEID, selectors)
	require.NoError(s.T(), err)
	staleNodeSelectors, err := s.ds.GetNodeSelectors(ctx, deletedNodeSPIFFEID, datastore.RequireCurrent)
	s.Require().NoError(err)
	s.Equal(selectors, staleNodeSelectors)

	// Initialize a new datastore to force a cleanup of stale node resolver entries
	dbPath := s.ds.db.connectionString
	databaseType := s.ds.db.databaseType
	err = s.ds.Close()
	s.Require().NoError(err)
	s.ds.db = nil
	err = s.ds.Configure(ctx, fmt.Sprintf(`
			database_type = "%s"
			log_sql = true
			connection_string = "%s"
            ro_connection_string = "%s"
		`, databaseType, dbPath, TestROConnString))
	s.Require().NoError(err)

	spiretest.AssertLogsContainEntries(s.T(), s.hook.AllEntries(), []spiretest.LogEntry{
		{
			Level:   logrus.InfoLevel,
			Message: "Deleted 4 stale node resolver entries",
		},
	})

	// Check that stale node selectors were deleted since the underlying attested node entry does not exist
	staleNodeSelectors, err = s.ds.GetNodeSelectors(ctx, deletedNodeSPIFFEID, datastore.RequireCurrent)
	s.Require().NoError(err)
	s.Empty(staleNodeSelectors)

	// Check that foo node selectors were not deleted because the attested node entry still exists
	nodeSelectors, err = s.ds.GetNodeSelectors(ctx, existentNode.SpiffeId, datastore.RequireCurrent)
	s.Require().NoError(err)
	s.Equal(selectors, nodeSelectors)
}

func (s *PluginSuite) TestMigration() {
	for schemaVersion := 0; schemaVersion < latestSchemaVersion; schemaVersion++ {
		s.T().Run(fmt.Sprintf("migration_from_schema_version_%d", schemaVersion), func(t *testing.T) {
			require := require.New(t)
			dbName := fmt.Sprintf("v%d.sqlite3", schemaVersion)
			dbPath := filepath.ToSlash(filepath.Join(s.dir, "migration-"+dbName))
			if runtime.GOOS == "windows" {
				dbPath = "/" + dbPath
			}
			dbURI := fmt.Sprintf("file://%s", dbPath)

			minimalDB := func() string {
				previousMinor := codeVersion
				if codeVersion.Minor == 0 {
					previousMinor.Major--
				} else {
					previousMinor.Minor--
				}
				return fmt.Sprintf(`
					CREATE TABLE "migrations" ("id" integer primary key autoincrement, "version" integer,"code_version" varchar(255) );
					INSERT INTO migrations("version", "code_version") VALUES (%d,%q);
				`, schemaVersion, previousMinor)
			}

			prepareDB := func(migrationSupported bool) {
				dump := migrationDumps[schemaVersion]
				if migrationSupported {
					require.NotEmpty(dump, "no migration dump set up for schema version")
				} else {
					require.Empty(dump, "migration dump exists for unsupported schema version")
					dump = minimalDB()
				}
				dumpDB(t, dbPath, dump)
				err := s.ds.Configure(ctx, fmt.Sprintf(`
					database_type = "sqlite3"
					connection_string = %q
				`, dbURI))
				if migrationSupported {
					require.NoError(err)
				} else {
					require.EqualError(err, fmt.Sprintf("datastore-sql: migrating from schema version %d requires a previous SPIRE release; please follow the upgrade strategy at doc/upgrading.md", schemaVersion))
				}
			}
			switch schemaVersion {
			// All of these schema versions were migrated by previous versions
			// of SPIRE server and no longer have migration code.
			case 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20:
				prepareDB(false)
			case 21:
				prepareDB(true)
			default:
				t.Fatalf("no migration test added for schema version %d", schemaVersion)
			}
		})
	}
}

func (s *PluginSuite) TestPristineDatabaseMigrationValues() {
	var m Migration
	s.Require().NoError(s.ds.db.First(&m).Error)
	s.Equal(latestSchemaVersion, m.Version)
	s.Equal(codeVersion.String(), m.CodeVersion)
}

func (s *PluginSuite) TestRace() {
	next := int64(0)
	exp := time.Now().Add(time.Hour).Unix()

	testutil.RaceTest(s.T(), func(t *testing.T) {
		node := &common.AttestedNode{
			SpiffeId:            fmt.Sprintf("foo%d", atomic.AddInt64(&next, 1)),
			AttestationDataType: "aws-tag",
			CertSerialNumber:    "badcafe",
			CertNotAfter:        exp,
		}

		_, err := s.ds.CreateAttestedNode(ctx, node)
		require.NoError(t, err)
		_, err = s.ds.FetchAttestedNode(ctx, node.SpiffeId)
		require.NoError(t, err)
	})
}

func (s *PluginSuite) TestBindVar() {
	fn := func(n int) string {
		return fmt.Sprintf("$%d", n)
	}
	bound := bindVarsFn(fn, "SELECT whatever FROM foo WHERE x = ? AND y = ?")
	s.Require().Equal("SELECT whatever FROM foo WHERE x = $1 AND y = $2", bound)
}

func (s *PluginSuite) getTestDataFromJSONFile(filePath string, jsonValue interface{}) {
	entriesJSON, err := os.ReadFile(filePath)
	s.Require().NoError(err)

	err = json.Unmarshal(entriesJSON, &jsonValue)
	s.Require().NoError(err)
}

func (s *PluginSuite) fetchBundle(trustDomainID string) *common.Bundle {
	bundle, err := s.ds.FetchBundle(ctx, trustDomainID)
	s.Require().NoError(err)
	return bundle
}

func (s *PluginSuite) createBundle(trustDomainID string) *common.Bundle {
	bundle, err := s.ds.CreateBundle(ctx, bundleutil.BundleProtoFromRootCA(trustDomainID, s.cert))
	s.Require().NoError(err)
	return bundle
}

func (s *PluginSuite) createRegistrationEntry(entry *common.RegistrationEntry) *common.RegistrationEntry {
	registrationEntry, err := s.ds.CreateRegistrationEntry(ctx, entry)
	s.Require().NoError(err)
	s.Require().NotNil(registrationEntry)
	return registrationEntry
}

func (s *PluginSuite) deleteRegistrationEntry(entryID string) {
	_, err := s.ds.DeleteRegistrationEntry(ctx, entryID)
	s.Require().NoError(err)
}

func (s *PluginSuite) fetchRegistrationEntry(entryID string) *common.RegistrationEntry {
	registrationEntry, err := s.ds.FetchRegistrationEntry(ctx, entryID)
	s.Require().NoError(err)
	s.Require().NotNil(registrationEntry)
	return registrationEntry
}

func makeFederatedRegistrationEntry() *common.RegistrationEntry {
	return &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
		},
		SpiffeId:      "spiffe://example.org/foo",
		FederatesWith: []string{"spiffe://otherdomain.org"},
	}
}

func (s *PluginSuite) getNodeSelectors(spiffeID string, dataConsistency datastore.DataConsistency) []*common.Selector {
	if dataConsistency == datastore.TolerateStale && TestReadOnlyDelay != "" {
		time.Sleep(s.readOnlyDelay)
	}
	selectors, err := s.ds.GetNodeSelectors(ctx, spiffeID, dataConsistency)
	s.Require().NoError(err)
	return selectors
}

func (s *PluginSuite) listNodeSelectors(req *datastore.ListNodeSelectorsRequest) *datastore.ListNodeSelectorsResponse {
	resp, err := s.ds.ListNodeSelectors(ctx, req)
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	return resp
}

func (s *PluginSuite) setNodeSelectors(spiffeID string, selectors []*common.Selector) {
	err := s.ds.SetNodeSelectors(ctx, spiffeID, selectors)
	s.Require().NoError(err)
}

func (s *PluginSuite) TestConfigure() {
	tests := []struct {
		desc               string
		giveDBConfig       string
		expectMaxOpenConns int
		expectIdle         int
	}{
		{
			desc:               "defaults",
			expectMaxOpenConns: 0,
			// defined in database/sql
			expectIdle: 2,
		},
		{
			desc: "zero values",
			giveDBConfig: `
			max_open_conns = 0
			max_idle_conns = 0
			`,
			expectMaxOpenConns: 0,
			expectIdle:         0,
		},
		{
			desc: "custom values",
			giveDBConfig: `
			max_open_conns = 1000
			max_idle_conns = 50
			conn_max_lifetime = "10s"
			`,
			expectMaxOpenConns: 1000,
			expectIdle:         50,
		},
	}

	for _, tt := range tests {
		tt := tt
		s.T().Run(tt.desc, func(t *testing.T) {
			dbPath := filepath.ToSlash(filepath.Join(s.dir, "test-datastore-configure.sqlite3"))

			log, _ := test.NewNullLogger()

			p := New(log)
			err := p.Configure(ctx, fmt.Sprintf(`
				database_type = "sqlite3"
				log_sql = true
				connection_string = "%s"
				%s
			`, dbPath, tt.giveDBConfig))
			require.NoError(t, err)
			defer p.Close()

			db := p.db.DB.DB()
			require.Equal(t, tt.expectMaxOpenConns, db.Stats().MaxOpenConnections)

			// begin many queries simultaneously
			numQueries := 100
			var rowsList []*sql.Rows
			for i := 0; i < numQueries; i++ {
				rows, err := db.Query("SELECT * FROM bundles")
				require.NoError(t, err)
				rowsList = append(rowsList, rows)
			}

			// close all open queries, which results in idle connections
			for _, rows := range rowsList {
				require.NoError(t, rows.Close())
			}
			require.Equal(t, tt.expectIdle, db.Stats().Idle)
		})
	}
}

func (s *PluginSuite) assertEntryEqual(t *testing.T, expectEntry, createdEntry *common.RegistrationEntry, now int64) {
	require.NotEmpty(t, createdEntry.EntryId)
	createdEntry.EntryId = ""
	s.assertCreatedAtField(createdEntry, now)
	createdEntry.CreatedAt = expectEntry.CreatedAt
	spiretest.RequireProtoEqual(t, createdEntry, expectEntry)
}

func (s *PluginSuite) assertCreatedAtFields(result *datastore.ListRegistrationEntriesResponse, now int64) {
	for _, entry := range result.Entries {
		s.assertCreatedAtField(entry, now)
	}
}

func (s *PluginSuite) assertCreatedAtField(entry *common.RegistrationEntry, now int64) {
	// We can't compare the exact time because we don't have control over the clock used by the database.
	s.Assert().GreaterOrEqual(entry.CreatedAt, now)
	entry.CreatedAt = 0
}

// assertBundlesEqual asserts that the two bundle lists are equal independent
// of ordering.
func assertBundlesEqual(t *testing.T, expected, actual []*common.Bundle) {
	if !assert.Equal(t, len(expected), len(actual)) {
		return
	}

	es := map[string]*common.Bundle{}
	as := map[string]*common.Bundle{}

	for _, e := range expected {
		es[e.TrustDomainId] = e
	}

	for _, a := range actual {
		as[a.TrustDomainId] = a
	}

	for id, a := range as {
		e, ok := es[id]
		if assert.True(t, ok, "bundle %q was unexpected", id) {
			spiretest.AssertProtoEqual(t, e, a)
			delete(es, id)
		}
	}

	for id := range es {
		assert.Failf(t, "bundle %q was expected but not found", id)
	}
}

func wipePostgres(t *testing.T, connString string) {
	db, err := sql.Open("postgres", connString)
	require.NoError(t, err)
	defer db.Close()

	rows, err := db.Query(`SELECT tablename FROM pg_tables WHERE schemaname = 'public';`)
	require.NoError(t, err)
	defer rows.Close()

	dropTables(t, db, scanTableNames(t, rows))
}

func wipeMySQL(t *testing.T, connString string) {
	db, err := sql.Open("mysql", connString)
	require.NoError(t, err)
	defer db.Close()

	rows, err := db.Query(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'spire';`)
	require.NoError(t, err)
	defer rows.Close()

	dropTables(t, db, scanTableNames(t, rows))
}

func scanTableNames(t *testing.T, rows *sql.Rows) []string {
	var tableNames []string
	for rows.Next() {
		var tableName string
		err := rows.Scan(&tableName)
		require.NoError(t, err)
		tableNames = append(tableNames, tableName)
	}
	require.NoError(t, rows.Err())
	return tableNames
}

func dropTables(t *testing.T, db *sql.DB, tableNames []string) {
	for _, tableName := range tableNames {
		_, err := db.Exec("DROP TABLE IF EXISTS " + tableName + " CASCADE")
		require.NoError(t, err)
	}
}

// assertSelectorsEqual compares two selector maps for equality
// TODO: replace this with calls to Equal when we replace common.Selector with
// a normal struct that doesn't require special comparison (i.e. not a
// protobuf)
func assertSelectorsEqual(t *testing.T, expected, actual map[string][]*common.Selector, msgAndArgs ...interface{}) {
	type selector struct {
		Type  string
		Value string
	}
	convert := func(in map[string][]*common.Selector) map[string][]selector {
		out := make(map[string][]selector)
		for spiffeID, selectors := range in {
			for _, s := range selectors {
				out[spiffeID] = append(out[spiffeID], selector{Type: s.Type, Value: s.Value})
			}
		}
		return out
	}
	assert.Equal(t, convert(expected), convert(actual), msgAndArgs...)
}

func makeSelectors(vs ...string) []*common.Selector {
	var ss []*common.Selector
	for _, v := range vs {
		ss = append(ss, &common.Selector{Type: v, Value: v})
	}
	return ss
}

func bySelectors(match datastore.MatchBehavior, ss ...string) *datastore.BySelectors {
	return &datastore.BySelectors{
		Match:     match,
		Selectors: makeSelectors(ss...),
	}
}

func makeID(suffix string) string {
	return "spiffe://example.org/" + suffix
}

func createBundles(t *testing.T, ds *Plugin, trustDomains []string) {
	for _, td := range trustDomains {
		_, err := ds.CreateBundle(ctx, &common.Bundle{
			TrustDomainId: td,
			RootCas: []*common.Certificate{
				{
					DerBytes: []byte{1},
				},
			},
		})
		require.NoError(t, err)
	}
}

func requireURLFromString(t *testing.T, s string) *url.URL {
	url, err := url.Parse(s)
	if err != nil {
		require.FailNow(t, err.Error())
	}
	return url
}

func assertFederationRelationship(t *testing.T, exp, actual *datastore.FederationRelationship) {
	if exp == nil {
		assert.Nil(t, actual)
		return
	}
	assert.Equal(t, exp.BundleEndpointProfile, actual.BundleEndpointProfile)
	assert.Equal(t, exp.BundleEndpointURL, actual.BundleEndpointURL)
	assert.Equal(t, exp.EndpointSPIFFEID, actual.EndpointSPIFFEID)
	assert.Equal(t, exp.TrustDomain, actual.TrustDomain)
	spiretest.AssertProtoEqual(t, exp.TrustDomainBundle, actual.TrustDomainBundle)
}
