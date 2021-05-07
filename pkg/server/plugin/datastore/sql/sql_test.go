package sql

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	testutil "github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	ctx = context.Background()

	// The following are set by the linker during integration tests to
	// run these unit tests against various SQL backends.
	TestDialect      string
	TestConnString   string
	TestROConnString string
	// Replication to replica can take some time,
	// if specified, this configuration setting tells the duration to wait before running queries in stale databases
	TestStaleDelay string
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

	staleDelay time.Duration
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

	if TestStaleDelay != "" {
		delay, err := time.ParseDuration(TestStaleDelay)
		s.Require().NoError(err, "failed to parse stale delay")
		s.staleDelay = delay
	}
}

func (s *PluginSuite) SetupTest() {
	s.dir = s.TempDir()
	s.ds = s.newPlugin()
}

func (s *PluginSuite) TearDownTest() {
	s.ds.closeDB()
}

func (s *PluginSuite) newPlugin() *Plugin {
	log, _ := test.NewNullLogger()
	ds := New(log)

	// When the test suite is executed normally, we test against sqlite3 since
	// it requires no external dependencies. The integration test framework
	// builds the test harness for a specific dialect and connection string
	switch TestDialect {
	case "":
		s.nextID++
		dbPath := filepath.Join(s.dir, fmt.Sprintf("db%d.sqlite3", s.nextID))
		err := ds.Configure(fmt.Sprintf(`
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
		err := ds.Configure(fmt.Sprintf(`
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
		err := ds.Configure(fmt.Sprintf(`
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
	err := s.ds.Configure(`
		database_type = "wrong"
		connection_string = "bad"
	`)
	s.RequireErrorContains(err, "datastore-sql: unsupported database_type: wrong")
}

func (s *PluginSuite) TestInvalidMySQLConfiguration() {
	err := s.ds.Configure(`
		database_type = "mysql"
		connection_string = "username:@tcp(127.0.0.1)/spire_test"
	`)
	s.RequireErrorContains(err, "datastore-sql: invalid mysql config: missing parseTime=true param in connection_string")

	err = s.ds.Configure(`
		database_type = "mysql"
		ro_connection_string = "username:@tcp(127.0.0.1)/spire_test"
	`)
	s.RequireErrorContains(err, "datastore-sql: connection_string must be set")

	err = s.ds.Configure(`
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
	_, err = s.ds.UpdateBundle(ctx, &datastore.UpdateBundleRequest{Bundle: bundle})
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

	// fetch (with denormalized id)
	fb, err = s.ds.FetchBundle(ctx, "spiffe://fOO")
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

	// append
	aresp, err := s.ds.AppendBundle(ctx, &datastore.AppendBundleRequest{
		Bundle: bundle2,
	})
	s.Require().NoError(err)
	s.Require().NotNil(aresp.Bundle)
	s.AssertProtoEqual(appendedBundle, aresp.Bundle)

	// append identical
	aresp, err = s.ds.AppendBundle(ctx, &datastore.AppendBundleRequest{
		Bundle: bundle2,
	})
	s.Require().NoError(err)
	s.Require().NotNil(aresp.Bundle)
	s.AssertProtoEqual(appendedBundle, aresp.Bundle)

	// append on a new bundle
	bundle3 := bundleutil.BundleProtoFromRootCA("spiffe://bar", s.cacert)
	anresp, err := s.ds.AppendBundle(ctx, &datastore.AppendBundleRequest{
		Bundle: bundle3,
	})
	s.Require().NoError(err)
	s.AssertProtoEqual(bundle3, anresp.Bundle)

	// update with mask: RootCas
	uresp, err := s.ds.UpdateBundle(ctx, &datastore.UpdateBundleRequest{
		Bundle: bundle,
		InputMask: &common.BundleMask{
			RootCas: true,
		},
	})
	s.Require().NoError(err)
	s.AssertProtoEqual(bundle, uresp.Bundle)

	lresp, err = s.ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	s.Require().NoError(err)
	assertBundlesEqual(s.T(), []*common.Bundle{bundle, bundle3}, lresp.Bundles)

	// update with mask: RefreshHint
	bundle.RefreshHint = 60
	uresp, err = s.ds.UpdateBundle(ctx, &datastore.UpdateBundleRequest{
		Bundle: bundle,
		InputMask: &common.BundleMask{
			RefreshHint: true,
		},
	})
	s.Require().NoError(err)
	s.AssertProtoEqual(bundle, uresp.Bundle)

	lresp, err = s.ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	s.Require().NoError(err)
	assertBundlesEqual(s.T(), []*common.Bundle{bundle, bundle3}, lresp.Bundles)

	// update with mask: JwtSingingKeys
	bundle.JwtSigningKeys = []*common.PublicKey{{Kid: "jwt-key-1"}}
	uresp, err = s.ds.UpdateBundle(ctx, &datastore.UpdateBundleRequest{
		Bundle: bundle,
		InputMask: &common.BundleMask{
			JwtSigningKeys: true,
		},
	})
	s.Require().NoError(err)
	s.AssertProtoEqual(bundle, uresp.Bundle)

	lresp, err = s.ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	s.Require().NoError(err)
	assertBundlesEqual(s.T(), []*common.Bundle{bundle, bundle3}, lresp.Bundles)

	// update without mask
	uresp, err = s.ds.UpdateBundle(ctx, &datastore.UpdateBundleRequest{
		Bundle: bundle2,
	})
	s.Require().NoError(err)
	s.AssertProtoEqual(bundle2, uresp.Bundle)

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

	// delete (with denormalized id)
	err = s.ds.DeleteBundle(ctx, "spiffe://bAR", datastore.Restrict)
	s.Require().NoError(err)

	lresp, err = s.ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	s.Require().NoError(err)
	s.Empty(lresp.Bundles)
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
		byExpiresBefore    *wrapperspb.Int64Value
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
	_, err := s.ds.SetBundle(ctx, &datastore.SetBundleRequest{
		Bundle: bundle,
	})
	s.Require().NoError(err)
	s.RequireProtoEqual(bundle, s.fetchBundle("spiffe://foo"))

	// set the bundle and make sure it is updated
	_, err = s.ds.SetBundle(ctx, &datastore.SetBundleRequest{
		Bundle: bundle2,
	})
	s.Require().NoError(err)
	s.RequireProtoEqual(bundle2, s.fetchBundle("spiffe://foo"))
}

func (s *PluginSuite) TestBundlePrune() {
	// Setup
	// Create new bundle with two cert (one valid and one expired)
	bundle := bundleutil.BundleProtoFromRootCAs("spiffe://foo", []*x509.Certificate{s.cert, s.cacert})

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
	expiration := time.Now().Unix()
	presp, err := s.ds.PruneBundle(ctx, &datastore.PruneBundleRequest{
		TrustDomainId: "spiffe://notexistent",
		ExpiresBefore: expiration,
	})
	s.NoError(err)
	s.Equal(presp, &datastore.PruneBundleResponse{})

	// prune fails if internal prune bundle fails. For instance, if all certs are expired
	expiration = time.Now().Unix()
	presp, err = s.ds.PruneBundle(ctx, &datastore.PruneBundleRequest{
		TrustDomainId: bundle.TrustDomainId,
		ExpiresBefore: expiration,
	})
	s.AssertGRPCStatus(err, codes.Unknown, "prune failed: would prune all certificates")
	s.Nil(presp)

	// prune should remove expired certs
	presp, err = s.ds.PruneBundle(ctx, &datastore.PruneBundleRequest{
		TrustDomainId: bundle.TrustDomainId,
		ExpiresBefore: middleTime.Unix(),
	})
	s.NoError(err)
	s.NotNil(presp)
	s.True(presp.BundleChanged)

	// Fetch and verify pruned bundle is the expected
	expectedPrunedBundle := bundleutil.BundleProtoFromRootCAs("spiffe://foo", []*x509.Certificate{s.cert})
	expectedPrunedBundle.JwtSigningKeys = []*common.PublicKey{{NotAfter: nonExpiredKeyTime.Unix()}}
	fb, err := s.ds.FetchBundle(ctx, "spiffe://foo")
	s.Require().NoError(err)
	s.AssertProtoEqual(expectedPrunedBundle, fb)
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
	now := time.Now()
	expired := now.Add(-time.Hour)
	unexpired := now.Add(time.Hour)

	byBanned := func(value bool) *wrapperspb.BoolValue {
		return &wrapperspb.BoolValue{Value: value}
	}

	byExpiresBefore := func(t time.Time) *wrapperspb.Int64Value {
		return &wrapperspb.Int64Value{Value: t.Unix()}
	}

	makeAttestedNode := func(spiffeIDSuffix, attestationType string, notAfter time.Time, sn string, selectors ...string) *common.AttestedNode {
		return &common.AttestedNode{
			SpiffeId:            makeID(spiffeIDSuffix),
			AttestationDataType: attestationType,
			CertSerialNumber:    sn,
			CertNotAfter:        notAfter.Unix(),
			Selectors:           makeSelectors(selectors...),
		}
	}

	banned := ""
	unbanned := "IRRELEVANT"

	nodeA := makeAttestedNode("A", "T1", expired, unbanned, "S1")
	nodeB := makeAttestedNode("B", "T2", expired, unbanned, "S1")
	nodeC := makeAttestedNode("C", "T1", expired, unbanned, "S2")
	nodeD := makeAttestedNode("D", "T2", expired, unbanned, "S2")
	nodeE := makeAttestedNode("E", "T1", unexpired, banned, "S1", "S2")
	nodeF := makeAttestedNode("F", "T2", unexpired, banned, "S1", "S3")
	nodeG := makeAttestedNode("G", "T1", unexpired, banned, "S2", "S3")
	nodeH := makeAttestedNode("H", "T2", unexpired, banned, "S2", "S3")

	for _, tt := range []struct {
		test                string
		nodes               []*common.AttestedNode
		pageSize            int32
		byExpiresBefore     *wrapperspb.Int64Value
		byAttestationType   string
		bySelectors         *datastore.BySelectors
		byBanned            *wrapperspb.BoolValue
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
			byExpiresBefore:     byExpiresBefore(now),
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
			byBanned:            byBanned(true),
			expectNodesOut:      []*common.AttestedNode{nodeE, nodeF},
			expectPagedTokensIn: []string{"", "2", "3"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeE}, {nodeF}, {}},
		},
		{
			test:                "by unbanned",
			nodes:               []*common.AttestedNode{nodeA, nodeE, nodeF, nodeB},
			byBanned:            byBanned(false),
			expectNodesOut:      []*common.AttestedNode{nodeA, nodeB},
			expectPagedTokensIn: []string{"", "1", "4"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeA}, {nodeB}, {}},
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
		// By exact selector match
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
					defer s.ds.closeDB()

					// Create entries for the test. For convenience, map the actual
					// entry ID to the "test" entry ID, so we can easily pinpoint
					// which entries were unexpectedly missing or included in the
					// listing.
					for _, node := range tt.nodes {
						_, err := s.ds.CreateAttestedNode(ctx, node)
						require.NoError(t, err)
						_, err = s.ds.SetNodeSelectors(ctx, &datastore.SetNodeSelectorsRequest{
							Selectors: &datastore.NodeSelectors{
								SpiffeId:  node.SpiffeId,
								Selectors: node.Selectors,
							},
						})
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
						FetchSelectors:    withSelectors,
					}

					// Don't loop forever if there is a bug
					for i := 0; ; i++ {
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

	for _, tt := range []struct {
		name           string
		updateReq      *datastore.UpdateAttestedNodeRequest
		expUpdatedNode *common.AttestedNode
		expCode        codes.Code
		expMsg         string
	}{
		{
			name: "update non-existing attested node",
			updateReq: &datastore.UpdateAttestedNodeRequest{
				SpiffeId:         "non-existent-node-id",
				CertSerialNumber: updatedSerial,
				CertNotAfter:     updatedExpires,
			},
			expCode: codes.NotFound,
			expMsg:  _notFoundErrMsg,
		},
		{
			name: "update attested node with all false mask",
			updateReq: &datastore.UpdateAttestedNodeRequest{
				SpiffeId:            nodeID,
				CertSerialNumber:    updatedSerial,
				CertNotAfter:        updatedExpires,
				NewCertNotAfter:     updatedNewExpires,
				NewCertSerialNumber: updatedNewSerial,
				InputMask:           &common.AttestedNodeMask{},
			},
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
			updateReq: &datastore.UpdateAttestedNodeRequest{
				SpiffeId:            nodeID,
				CertSerialNumber:    updatedSerial,
				CertNotAfter:        updatedExpires,
				NewCertNotAfter:     updatedNewExpires,
				NewCertSerialNumber: updatedNewSerial,
				InputMask: &common.AttestedNodeMask{
					CertSerialNumber: true,
					NewCertNotAfter:  true,
				},
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
			updateReq: &datastore.UpdateAttestedNodeRequest{
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
			defer s.ds.closeDB()

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
			uresp, err := s.ds.UpdateAttestedNode(ctx, tt.updateReq)
			s.RequireGRPCStatus(err, tt.expCode, tt.expMsg)
			if tt.expCode != codes.OK {
				s.Require().Nil(uresp)
				return
			}
			s.Require().NoError(err)
			s.Require().NotNil(uresp)
			s.RequireProtoEqual(tt.expUpdatedNode, uresp.Node)

			// Check a fresh fetch shows the updated attested node
			attestedNode, err := s.ds.FetchAttestedNode(ctx, tt.updateReq.SpiffeId)
			s.Require().NoError(err)
			s.Require().NotNil(attestedNode)
			s.RequireProtoEqual(tt.expUpdatedNode, attestedNode)
		})
	}
}

func (s *PluginSuite) TestDeleteAttestedNode() {
	entry := &common.AttestedNode{
		SpiffeId:            "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}

	// delete it before it exists
	_, err := s.ds.DeleteAttestedNode(ctx, entry.SpiffeId)
	s.RequireGRPCStatus(err, codes.NotFound, _notFoundErrMsg)

	_, err = s.ds.CreateAttestedNode(ctx, entry)
	s.Require().NoError(err)

	deletedNode, err := s.ds.DeleteAttestedNode(ctx, entry.SpiffeId)
	s.Require().NoError(err)
	s.AssertProtoEqual(entry, deletedNode)

	attestedNode, err := s.ds.FetchAttestedNode(ctx, entry.SpiffeId)
	s.Require().NoError(err)
	s.Nil(attestedNode)
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
	selectors := s.getNodeSelectors("foo", true)
	s.Require().Empty(selectors)
	selectors = s.getNodeSelectors("foo", false)
	s.Require().Empty(selectors)

	// set selectors on foo and bar
	s.setNodeSelectors("foo", foo1)
	s.setNodeSelectors("bar", bar)

	// get foo selectors
	selectors = s.getNodeSelectors("foo", true)
	s.RequireProtoListEqual(foo1, selectors)
	selectors = s.getNodeSelectors("foo", false)
	s.RequireProtoListEqual(foo1, selectors)

	// replace foo selectors
	s.setNodeSelectors("foo", foo2)
	selectors = s.getNodeSelectors("foo", true)
	s.RequireProtoListEqual(foo2, selectors)
	selectors = s.getNodeSelectors("foo", false)
	s.RequireProtoListEqual(foo2, selectors)

	// delete foo selectors
	s.setNodeSelectors("foo", nil)
	selectors = s.getNodeSelectors("foo", true)
	s.Require().Empty(selectors)
	selectors = s.getNodeSelectors("foo", false)
	s.Require().Empty(selectors)

	// get bar selectors (make sure they weren't impacted by deleting foo)
	selectors = s.getNodeSelectors("bar", true)
	s.RequireProtoListEqual(bar, selectors)
	// get bar selectors (make sure they weren't impacted by deleting foo)
	selectors = s.getNodeSelectors("bar", false)
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

	allAttNodesToCreate := append(nonExpiredAttNodes, expiredAttNodes...)
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
			ValidAt: &timestamppb.Timestamp{
				Seconds: now.Unix(),
			},
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
				_, err := s.ds.SetNodeSelectors(ctx, &datastore.SetNodeSelectorsRequest{
					Selectors: &datastore.NodeSelectors{
						SpiffeId:  id,
						Selectors: selectors,
					},
				})
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
	var validRegistrationEntries []*common.RegistrationEntry
	s.getTestDataFromJSONFile(filepath.Join("testdata", "valid_registration_entries.json"), &validRegistrationEntries)

	for _, validRegistrationEntry := range validRegistrationEntries {
		registrationEntry, err := s.ds.CreateRegistrationEntry(ctx, validRegistrationEntry)
		s.Require().NoError(err)
		s.Require().NotNil(registrationEntry)
		s.NotEmpty(registrationEntry.EntryId)
		registrationEntry.EntryId = ""
		s.RequireProtoEqual(registrationEntry, validRegistrationEntry)
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
	entry := &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
			{Type: "Type2", Value: "Value2"},
			{Type: "Type3", Value: "Value3"},
		},
		SpiffeId: "SpiffeId",
		ParentId: "ParentId",
		Ttl:      1,
		DnsNames: []string{
			"abcd.efg",
			"somehost",
		},
	}

	createdRegistrationEntry, err := s.ds.CreateRegistrationEntry(ctx, entry)
	s.Require().NoError(err)

	fetchedRegistrationEntry, err := s.ds.FetchRegistrationEntry(ctx, createdRegistrationEntry.EntryId)
	s.Require().NoError(err)
	s.RequireProtoEqual(createdRegistrationEntry, fetchedRegistrationEntry)
}

func (s *PluginSuite) TestPruneRegistrationEntries() {
	now := time.Now().Unix()
	entry := &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
			{Type: "Type2", Value: "Value2"},
			{Type: "Type3", Value: "Value3"},
		},
		SpiffeId:    "SpiffeId",
		ParentId:    "ParentId",
		Ttl:         1,
		EntryExpiry: now,
	}

	createdRegistrationEntry, err := s.ds.CreateRegistrationEntry(ctx, entry)
	s.Require().NoError(err)

	// Ensure we don't prune valid entries, wind clock back 10s
	_, err = s.ds.PruneRegistrationEntries(ctx, &datastore.PruneRegistrationEntriesRequest{
		ExpiresBefore: now - 10,
	})
	s.Require().NoError(err)

	fetchedRegistrationEntry, err := s.ds.FetchRegistrationEntry(ctx, createdRegistrationEntry.EntryId)
	s.Require().NoError(err)
	s.Equal(createdRegistrationEntry, fetchedRegistrationEntry)

	// Ensure we don't prune on the exact ExpiresBefore
	_, err = s.ds.PruneRegistrationEntries(ctx, &datastore.PruneRegistrationEntriesRequest{
		ExpiresBefore: now,
	})
	s.Require().NoError(err)

	fetchedRegistrationEntry, err = s.ds.FetchRegistrationEntry(ctx, createdRegistrationEntry.EntryId)
	s.Require().NoError(err)
	s.Equal(createdRegistrationEntry, fetchedRegistrationEntry)

	// Ensure we prune old entries
	_, err = s.ds.PruneRegistrationEntries(ctx, &datastore.PruneRegistrationEntriesRequest{
		ExpiresBefore: now + 10,
	})
	s.Require().NoError(err)

	fetchedRegistrationEntry, err = s.ds.FetchRegistrationEntry(ctx, createdRegistrationEntry.EntryId)
	s.Require().NoError(err)
	s.Nil(fetchedRegistrationEntry)
}

func (s *PluginSuite) TestFetchInexistentRegistrationEntry() {
	fetchedRegistrationEntry, err := s.ds.FetchRegistrationEntry(ctx, "INEXISTENT")
	s.Require().NoError(err)
	s.Require().Nil(fetchedRegistrationEntry)
}

func (s *PluginSuite) TestListRegistrationEntries() {
	s.testListRegistrationEntries(false)
	s.testListRegistrationEntries(true)

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

func (s *PluginSuite) testListRegistrationEntries(tolerateStale bool) {
	byID := func(suffix string) *wrapperspb.StringValue {
		return &wrapperspb.StringValue{Value: makeID(suffix)}
	}

	byFederatesWith := func(match datastore.MatchBehavior, trustDomainIDs ...string) *datastore.ByFederatesWith {
		return &datastore.ByFederatesWith{
			TrustDomains: trustDomainIDs,
			Match:        match,
		}
	}

	makeEntry := func(parentIDSuffix, spiffeIDSuffix string, selectors ...string) *common.RegistrationEntry {
		return &common.RegistrationEntry{
			EntryId:   fmt.Sprintf("%s%s%s", parentIDSuffix, spiffeIDSuffix, strings.Join(selectors, "")),
			ParentId:  makeID(parentIDSuffix),
			SpiffeId:  makeID(spiffeIDSuffix),
			Selectors: makeSelectors(selectors...),
		}
	}

	foobarAB1 := makeEntry("foo", "bar", "A", "B")
	foobarAB1.FederatesWith = []string{"spiffe://federated1.test"}
	foobarAD12 := makeEntry("foo", "bar", "A", "D")
	foobarAD12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}
	foobarCB2 := makeEntry("foo", "bar", "C", "B")
	foobarCB2.FederatesWith = []string{"spiffe://federated2.test"}
	foobarCD12 := makeEntry("foo", "bar", "C", "D")
	foobarCD12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}

	foobarB := makeEntry("foo", "bar", "B")

	foobuzAD := makeEntry("foo", "buz", "A", "D")
	foobuzCD := makeEntry("foo", "buz", "C", "D")

	bazbarAB1 := makeEntry("baz", "bar", "A", "B")
	bazbarAB1.FederatesWith = []string{"spiffe://federated1.test"}
	bazbarAD12 := makeEntry("baz", "bar", "A", "D")
	bazbarAD12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}
	bazbarCB2 := makeEntry("baz", "bar", "C", "B")
	bazbarCB2.FederatesWith = []string{"spiffe://federated2.test"}
	bazbarCD12 := makeEntry("baz", "bar", "C", "D")
	bazbarCD12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}

	bazbuzAB := makeEntry("baz", "buz", "A", "B")
	bazbuzB := makeEntry("baz", "buz", "B")
	bazbuzCD := makeEntry("baz", "buz", "C", "D")

	zizzazX := makeEntry("ziz", "zaz", "X")

	for _, tt := range []struct {
		test                  string
		entries               []*common.RegistrationEntry
		pageSize              int32
		byParentID            *wrapperspb.StringValue
		bySpiffeID            *wrapperspb.StringValue
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
			byParentID:            byID("foo"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1, foobarCB2},
			expectPagedTokensIn:   []string{"", "1", "3"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarCB2}, {}},
		},
		// by SPIFFE ID
		{
			test:                  "by SPIFFE ID",
			entries:               []*common.RegistrationEntry{foobarAB1, foobuzAD, foobarCB2, foobuzCD},
			bySpiffeID:            byID("bar"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1, foobarCB2},
			expectPagedTokensIn:   []string{"", "1", "3"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {foobarCB2}, {}},
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
		// by parent ID and spiffe ID
		{
			test:                  "by parent ID and SPIFFE ID",
			entries:               []*common.RegistrationEntry{foobarAB1, foobuzAD, bazbarCB2, bazbuzCD},
			byParentID:            byID("foo"),
			bySpiffeID:            byID("bar"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1},
			expectPagedTokensIn:   []string{"", "1"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}},
		},
		// by parent ID and selector
		{
			test:                  "by parent ID and exact selector",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB},
			byParentID:            byID("foo"),
			bySelectors:           bySelectors(datastore.Exact, "B"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarB},
			expectPagedTokensIn:   []string{"", "1"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {}},
		},
		{
			test:                  "by parent ID and exact selectors",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB},
			byParentID:            byID("foo"),
			bySelectors:           bySelectors(datastore.Exact, "A", "B"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1},
			expectPagedTokensIn:   []string{"", "2"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}},
		},
		{
			test:                  "by parent ID and subset selector",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB},
			byParentID:            byID("foo"),
			bySelectors:           bySelectors(datastore.Subset, "B"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarB},
			expectPagedTokensIn:   []string{"", "1"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {}},
		},
		{
			test:                  "by parent ID and subset selectors",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD},
			byParentID:            byID("foo"),
			bySelectors:           bySelectors(datastore.Subset, "A", "B", "Z"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarB, foobarAB1},
			expectPagedTokensIn:   []string{"", "1", "2"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {foobarAB1}, {}},
		},
		{
			test:                  "by parent ID and subset selectors no match",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD},
			byParentID:            byID("foo"),
			bySelectors:           bySelectors(datastore.Subset, "C", "Z"),
			expectEntriesOut:      []*common.RegistrationEntry{},
			expectPagedTokensIn:   []string{""},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{}},
		},
		// by parent ID and federates with
		{
			test:                  "by parentID and federatesWith one subset",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12},
			byParentID:            byID("baz"),
			byFederatesWith:       byFederatesWith(datastore.Subset, "spiffe://federated1.test"),
			expectEntriesOut:      []*common.RegistrationEntry{bazbarAB1},
			expectPagedTokensIn:   []string{"", "6"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAB1}, {}},
		},
		{
			test:                  "by parentID and federatesWith many subset",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12},
			byParentID:            byID("baz"),
			byFederatesWith:       byFederatesWith(datastore.Subset, "spiffe://federated2.test", "spiffe://federated3.test"),
			expectEntriesOut:      []*common.RegistrationEntry{bazbarCB2},
			expectPagedTokensIn:   []string{"", "8"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarCB2}, {}},
		},
		{
			test:                  "by parentID and federatesWith one exact",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12},
			byParentID:            byID("baz"),
			byFederatesWith:       byFederatesWith(datastore.Exact, "spiffe://federated1.test"),
			expectEntriesOut:      []*common.RegistrationEntry{bazbarAB1},
			expectPagedTokensIn:   []string{"", "6"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAB1}, {}},
		},
		{
			test:                  "by parentID and federatesWith many exact",
			entries:               []*common.RegistrationEntry{foobarAB1, foobarAD12, foobarCB2, foobarCD12, zizzazX, bazbarAB1, bazbarAD12, bazbarCB2, bazbarCD12},
			byParentID:            byID("baz"),
			byFederatesWith:       byFederatesWith(datastore.Exact, "spiffe://federated1.test", "spiffe://federated2.test"),
			expectEntriesOut:      []*common.RegistrationEntry{bazbarAD12, bazbarCD12},
			expectPagedTokensIn:   []string{"", "7", "9"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{bazbarAD12}, {bazbarCD12}, {}},
		},
		// by SPIFFE ID and selector
		{
			test:                  "by SPIFFE ID and exact selector",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB},
			bySpiffeID:            byID("bar"),
			bySelectors:           bySelectors(datastore.Exact, "B"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarB},
			expectPagedTokensIn:   []string{"", "1"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {}},
		},
		{
			test:                  "by SPIFFE ID and exact selectors",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB},
			bySpiffeID:            byID("bar"),
			bySelectors:           bySelectors(datastore.Exact, "A", "B"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarAB1},
			expectPagedTokensIn:   []string{"", "2"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarAB1}, {}},
		},
		{
			test:                  "by SPIFFE ID and subset selector",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbuzB, bazbuzAB},
			bySpiffeID:            byID("bar"),
			bySelectors:           bySelectors(datastore.Subset, "B"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarB},
			expectPagedTokensIn:   []string{"", "1"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {}},
		},
		{
			test:                  "by SPIFFE ID and subset selectors",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD},
			bySpiffeID:            byID("bar"),
			bySelectors:           bySelectors(datastore.Subset, "A", "B", "Z"),
			expectEntriesOut:      []*common.RegistrationEntry{foobarB, foobarAB1},
			expectPagedTokensIn:   []string{"", "1", "2"},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{foobarB}, {foobarAB1}, {}},
		},
		{
			test:                  "by SPIFFE ID and subset selectors no match",
			entries:               []*common.RegistrationEntry{foobarB, foobarAB1, bazbarCB2, bazbuzCD},
			bySpiffeID:            byID("bar"),
			bySelectors:           bySelectors(datastore.Subset, "C", "Z"),
			expectEntriesOut:      []*common.RegistrationEntry{},
			expectPagedTokensIn:   []string{""},
			expectPagedEntriesOut: [][]*common.RegistrationEntry{{}},
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
			if tolerateStale {
				name += " stale"
			}
			s.T().Run(name, func(t *testing.T) {
				s.ds = s.newPlugin()
				defer s.ds.closeDB()

				s.createBundle("spiffe://federated1.test")
				s.createBundle("spiffe://federated2.test")

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
				if tolerateStale && s.staleDelay > 0 {
					time.Sleep(s.staleDelay)
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
				req := &datastore.ListRegistrationEntriesRequest{
					Pagination:      pagination,
					ByParentId:      tt.byParentID,
					BySpiffeId:      tt.bySpiffeID,
					BySelectors:     tt.bySelectors,
					ByFederatesWith: tt.byFederatesWith,
				}

				// Don't loop forever if there is a bug
				for i := 0; ; i++ {
					if i > len(tt.entries) {
						require.FailNowf(t, "Exhausted paging limit in test", "tokens=%q spiffeids=%q", tokensIn, actualIDsOut)
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

					var idSet []string
					for _, entry := range resp.Entries {
						entryID, ok := entryIDMap[entry.EntryId]
						require.True(t, ok, "entry with id %q was not created by this test", entry.EntryId)
						idSet = append(idSet, entryID)
					}
					actualIDsOut = append(actualIDsOut, idSet)

					if resp.Pagination == nil || resp.Pagination.Token == "" {
						break
					}
					req.Pagination = resp.Pagination
				}

				expectEntriesOut := tt.expectPagedEntriesOut
				if !withPagination {
					expectEntriesOut = [][]*common.RegistrationEntry{tt.expectEntriesOut}
				}

				var expectIDsOut [][]string
				for _, entrySet := range expectEntriesOut {
					var idSet []string
					for _, entry := range entrySet {
						idSet = append(idSet, entry.EntryId)
					}
					expectIDsOut = append(expectIDsOut, idSet)
				}

				if withPagination {
					assert.Equal(t, tt.expectPagedTokensIn, tokensIn, "unexpected request tokens")
				} else {
					assert.Empty(t, tokensIn, "unexpected request tokens")
				}
				assert.Equal(t, expectIDsOut, actualIDsOut, "unexpected response entries")
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
		SpiffeId: "spiffe://example.org/foo",
		ParentId: "spiffe://example.org/bar",
		Ttl:      1,
	})

	entry.Ttl = 2
	entry.Admin = true
	entry.Downstream = true

	updateRegistrationEntryResponse, err := s.ds.UpdateRegistrationEntry(ctx, &datastore.UpdateRegistrationEntryRequest{
		Entry: entry,
	})
	s.Require().NoError(err)
	s.Require().NotNil(updateRegistrationEntryResponse)

	registrationEntry, err := s.ds.FetchRegistrationEntry(ctx, entry.EntryId)
	s.Require().NoError(err)
	s.Require().NotNil(registrationEntry)
	s.RequireProtoEqual(updateRegistrationEntryResponse.Entry, registrationEntry)

	entry.EntryId = "badid"
	_, err = s.ds.UpdateRegistrationEntry(ctx, &datastore.UpdateRegistrationEntryRequest{
		Entry: entry,
	})
	s.RequireGRPCStatus(err, codes.NotFound, _notFoundErrMsg)
}

func (s *PluginSuite) TestUpdateRegistrationEntryWithMask() {
	// There are 9 fields in a registration entry. Of these, 3 have some validation in the SQL
	// layer. In this test, we update each of the 9 fields and make sure update works, and also check
	// with the mask value false to make sure nothing changes. For the 3 fields that have validation
	// we try with good data, bad data, and with or without a mask (so 4 cases each.)

	// Note that most of the input validation is done in the API layer and has more extensive tests there.
	oldEntry := &common.RegistrationEntry{
		ParentId:      "spiffe://example.org/oldParentId",
		SpiffeId:      "spiffe://example.org/oldSpiffeId",
		Ttl:           1000,
		Selectors:     []*common.Selector{{Type: "Type1", Value: "Value1"}},
		FederatesWith: []string{"spiffe://dom1.org"},
		Admin:         false,
		EntryExpiry:   1000,
		DnsNames:      []string{"dns1"},
		Downstream:    false,
	}
	newEntry := &common.RegistrationEntry{
		ParentId:      "spiffe://example.org/oldParentId",
		SpiffeId:      "spiffe://example.org/newSpiffeId",
		Ttl:           1000,
		Selectors:     []*common.Selector{{Type: "Type2", Value: "Value2"}},
		FederatesWith: []string{"spiffe://dom2.org"},
		Admin:         false,
		EntryExpiry:   1000,
		DnsNames:      []string{"dns2"},
		Downstream:    false,
	}
	badEntry := &common.RegistrationEntry{
		ParentId:      "not a good parent id",
		SpiffeId:      "",
		Ttl:           -1000,
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
		// TTL FIELD -- This field is validated so we check with good and bad data
		{name: "Update TTL, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{Ttl: true},
			update: func(e *common.RegistrationEntry) { e.Ttl = newEntry.Ttl },
			result: func(e *common.RegistrationEntry) { e.Ttl = newEntry.Ttl }},
		{name: "Update TTL, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{Ttl: false},
			update: func(e *common.RegistrationEntry) { e.Ttl = badEntry.Ttl },
			result: func(e *common.RegistrationEntry) {}},
		{name: "Update TTL, Bad Data, Mask True",
			mask:   &common.RegistrationEntryMask{Ttl: true},
			update: func(e *common.RegistrationEntry) { e.Ttl = badEntry.Ttl },
			err:    errors.New("invalid registration entry: TTL is not set")},
		{name: "Update TTL, Bad Data, Mask False",
			mask:   &common.RegistrationEntryMask{Ttl: false},
			update: func(e *common.RegistrationEntry) { e.Ttl = badEntry.Ttl },
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
			mask:   &common.RegistrationEntryMask{Selectors: false},
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
		// This should update all fields
		{name: "Test With Nil Mask",
			mask:   nil,
			update: func(e *common.RegistrationEntry) { proto.Merge(e, oldEntry) },
			result: func(e *common.RegistrationEntry) {}},
	} {
		tt := testcase
		s.Run(tt.name, func() {
			registrationEntry := s.createRegistrationEntry(oldEntry)
			id := registrationEntry.EntryId

			updateEntry := &common.RegistrationEntry{}
			tt.update(updateEntry)
			updateEntry.EntryId = id
			updateRegistrationEntryResponse, err := s.ds.UpdateRegistrationEntry(ctx, &datastore.UpdateRegistrationEntryRequest{
				Entry: updateEntry,
				Mask:  tt.mask,
			})

			if tt.err != nil {
				s.Require().Error(tt.err)
				return
			}

			s.Require().NoError(err)
			s.Require().NotNil(updateRegistrationEntryResponse)
			expectedResult := proto.Clone(oldEntry).(*common.RegistrationEntry)
			tt.result(expectedResult)
			expectedResult.EntryId = id
			expectedResult.RevisionNumber++
			s.RequireProtoEqual(expectedResult, updateRegistrationEntryResponse.Entry)

			// Fetch and check the results match expectations
			registrationEntry, err = s.ds.FetchRegistrationEntry(ctx, id)
			s.Require().NoError(err)
			s.Require().NotNil(registrationEntry)

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
		SpiffeId: "spiffe://example.org/foo",
		ParentId: "spiffe://example.org/bar",
		Ttl:      1,
	})

	s.createRegistrationEntry(&common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type3", Value: "Value3"},
			{Type: "Type4", Value: "Value4"},
			{Type: "Type5", Value: "Value5"},
		},
		SpiffeId: "spiffe://example.org/baz",
		ParentId: "spiffe://example.org/bat",
		Ttl:      2,
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
			for _, entry := range test.registrationEntries {
				registrationEntry, err := ds.CreateRegistrationEntry(ctx, entry)
				require.NoError(t, err)
				require.NotNil(t, registrationEntry)
				entry.EntryId = registrationEntry.EntryId
			}
			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				ByParentId: &wrapperspb.StringValue{
					Value: test.parentID,
				},
			})
			require.NoError(t, err)
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestListSelectorEntries() {
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
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestListEntriesBySelectorSubset() {
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
			s.RequireProtoListEqual(test.expectedList, result.Entries)
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

	// verify that the registeration entry has been deleted
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
	joinToken.Expiry = now.Add(time.Second * 10)
	err = s.ds.PruneJoinTokens(ctx, now.Add(time.Second*10))
	s.Require().NoError(err)

	resp, err = s.ds.FetchJoinToken(ctx, joinToken.Token)
	s.Require().NoError(err)
	s.Nil(resp)
}

func (s *PluginSuite) TestDisabledMigrationBreakingChanges() {
	dbVersion := 8

	dbName := fmt.Sprintf("v%d.sqlite3", dbVersion)
	dbPath := filepath.Join(s.dir, "unsafe-disabled-migration-"+dbName)
	dump := migrationDump(dbVersion)
	s.Require().NotEmpty(dump, "no migration dump set up for version %d", dbVersion)
	s.Require().NoError(dumpDB(dbPath, dump), "error with DB dump for version %d", dbVersion)

	// configure the datastore to use the new database
	err := s.ds.Configure(fmt.Sprintf(`
		database_type = "sqlite3"
		connection_string = "file://%s"
		disable_migration = true
	`, dbPath))
	s.Require().EqualError(err, "datastore-sql: auto-migration must be enabled for current DB")
}

func (s *PluginSuite) TestMigration() {
	for i := 0; i < latestSchemaVersion; i++ {
		dbName := fmt.Sprintf("v%d.sqlite3", i)
		dbPath := filepath.Join(s.dir, "migration-"+dbName)
		dbURI := fmt.Sprintf("file://%s", dbPath)
		dump := migrationDump(i)
		s.Require().NotEmpty(dump, "no migration dump set up for version %d", i)
		s.Require().NoError(dumpDB(dbPath, dump), "error with DB dump for version %d", i)

		// configure the datastore to use the new database
		err := s.ds.Configure(fmt.Sprintf(`
			database_type = "sqlite3"
			connection_string = "file://%s"
		`, dbPath))
		s.Require().NoError(err)

		switch i {
		case 0:
			// the v0 database has two bundles. the spiffe://otherdomain.org
			// bundle has been soft-deleted. after migration, it should not
			// exist. if we try and create a bundle with the same id, it should
			// fail if the migration did not run, due to uniqueness
			// constraints.
			_, err := s.ds.CreateBundle(context.Background(), bundleutil.BundleProtoFromRootCAs("spiffe://otherdomain.org", nil))
			s.Require().NoError(err)
		case 1:
			// registration entries should gain the federates_with column.
			// creating a new registration entry with a federated trust domain
			// should be sufficient to test.
			s.createBundle("spiffe://otherdomain.org")
			s.createRegistrationEntry(&common.RegistrationEntry{
				SpiffeId:      "spiffe://example.org/foo",
				Selectors:     []*common.Selector{{Type: "TYPE", Value: "VALUE"}},
				FederatesWith: []string{"spiffe://otherdomain.org"},
			})
		case 2:
			// assert that SPIFFE IDs in bundles, attested nodes, node selectors, and registration entries
			// are all normalized.
			bundlesResp, err := s.ds.ListBundles(context.Background(), &datastore.ListBundlesRequest{})
			s.Require().NoError(err)
			s.Require().Len(bundlesResp.Bundles, 2)
			s.Require().Equal("spiffe://example.org", bundlesResp.Bundles[0].TrustDomainId)
			s.Require().Equal("spiffe://otherdomain.test", bundlesResp.Bundles[1].TrustDomainId)

			attestedNodesResp, err := s.ds.ListAttestedNodes(context.Background(), &datastore.ListAttestedNodesRequest{})
			s.Require().NoError(err)
			s.Require().Len(attestedNodesResp.Nodes, 1)
			s.Require().Equal("spiffe://example.org/spire/agent/join_token/13f1db93-6018-4496-8e77-6de440a174ed", attestedNodesResp.Nodes[0].SpiffeId)

			nodeSelectorsResp, err := s.ds.GetNodeSelectors(context.Background(), &datastore.GetNodeSelectorsRequest{
				SpiffeId:      "spiffe://example.org/spire/agent/join_token/13f1db93-6018-4496-8e77-6de440a174ed",
				TolerateStale: true,
			})
			s.Require().NoError(err)
			s.Require().NotNil(nodeSelectorsResp.Selectors)
			s.Require().Equal("spiffe://example.org/spire/agent/join_token/13f1db93-6018-4496-8e77-6de440a174ed", nodeSelectorsResp.Selectors.SpiffeId)

			entriesResp, err := s.ds.ListRegistrationEntries(context.Background(), &datastore.ListRegistrationEntriesRequest{})
			s.Require().NoError(err)
			s.Require().Len(entriesResp.Entries, 2)
			util.SortRegistrationEntries(entriesResp.Entries)
			s.Require().Equal("spiffe://example.org/nODe", entriesResp.Entries[0].ParentId)
			s.Require().Equal("spiffe://example.org/bLOg", entriesResp.Entries[0].SpiffeId)
			s.Require().Len(entriesResp.Entries[0].FederatesWith, 1)
			s.Require().Equal("spiffe://otherdomain.test", entriesResp.Entries[0].FederatesWith[0])
			s.Require().Equal("spiffe://example.org/spire/agent/join_token/13f1db93-6018-4496-8e77-6de440a174ed", entriesResp.Entries[1].ParentId)
			s.Require().Equal("spiffe://example.org/nODe", entriesResp.Entries[1].SpiffeId)
			s.Require().Len(entriesResp.Entries[1].FederatesWith, 0)
		case 3:
			bundlesResp, err := s.ds.ListBundles(context.Background(), &datastore.ListBundlesRequest{})
			s.Require().NoError(err)
			s.Require().Len(bundlesResp.Bundles, 2)
			s.Require().Equal("spiffe://example.org", bundlesResp.Bundles[0].TrustDomainId)
			s.Require().Len(bundlesResp.Bundles[0].RootCas, 3)
			s.Require().Equal("spiffe://otherdomain.test", bundlesResp.Bundles[1].TrustDomainId)
			s.Require().Len(bundlesResp.Bundles[1].RootCas, 1)
		case 4:
			resp, err := s.ds.ListRegistrationEntries(context.Background(), &datastore.ListRegistrationEntriesRequest{})
			s.Require().NoError(err)
			s.Require().Len(resp.Entries, 1)
			s.Require().False(resp.Entries[0].Admin)

			resp.Entries[0].Admin = true
			_, err = s.ds.UpdateRegistrationEntry(context.Background(), &datastore.UpdateRegistrationEntryRequest{
				Entry: resp.Entries[0],
			})
			s.Require().NoError(err)

			resp, err = s.ds.ListRegistrationEntries(context.Background(), &datastore.ListRegistrationEntriesRequest{})
			s.Require().NoError(err)
			s.Require().Len(resp.Entries, 1)
			s.Require().True(resp.Entries[0].Admin)
		case 5:
			resp, err := s.ds.ListRegistrationEntries(context.Background(), &datastore.ListRegistrationEntriesRequest{})
			s.Require().NoError(err)
			s.Require().Len(resp.Entries, 1)
			s.Require().False(resp.Entries[0].Downstream)

			resp.Entries[0].Downstream = true
			_, err = s.ds.UpdateRegistrationEntry(context.Background(), &datastore.UpdateRegistrationEntryRequest{
				Entry: resp.Entries[0],
			})
			s.Require().NoError(err)

			resp, err = s.ds.ListRegistrationEntries(context.Background(), &datastore.ListRegistrationEntriesRequest{})
			s.Require().NoError(err)
			s.Require().Len(resp.Entries, 1)
			s.Require().True(resp.Entries[0].Downstream)
		case 6:
			// ensure implementation of new expiry field
			resp, err := s.ds.ListRegistrationEntries(context.Background(), &datastore.ListRegistrationEntriesRequest{})
			s.Require().NoError(err)
			s.Require().Len(resp.Entries, 1)
			s.Require().Zero(resp.Entries[0].EntryExpiry)

			expiryVal := time.Now().Unix()
			resp.Entries[0].EntryExpiry = expiryVal
			_, err = s.ds.UpdateRegistrationEntry(context.Background(), &datastore.UpdateRegistrationEntryRequest{
				Entry: resp.Entries[0],
			})
			s.Require().NoError(err)

			resp, err = s.ds.ListRegistrationEntries(context.Background(), &datastore.ListRegistrationEntriesRequest{})
			s.Require().NoError(err)
			s.Require().Len(resp.Entries, 1)
			s.Require().Equal(expiryVal, resp.Entries[0].EntryExpiry)
		case 7:
			// ensure implementation of new dns field
			resp, err := s.ds.ListRegistrationEntries(context.Background(), &datastore.ListRegistrationEntriesRequest{})
			s.Require().NoError(err)
			s.Require().Len(resp.Entries, 1)
			s.Require().Empty(resp.Entries[0].DnsNames)

			resp.Entries[0].DnsNames = []string{"abcd.efg"}
			_, err = s.ds.UpdateRegistrationEntry(context.Background(), &datastore.UpdateRegistrationEntryRequest{
				Entry: resp.Entries[0],
			})
			s.Require().NoError(err)

			resp, err = s.ds.ListRegistrationEntries(context.Background(), &datastore.ListRegistrationEntriesRequest{})
			s.Require().NoError(err)
			s.Require().Len(resp.Entries, 1)
			s.Require().Len(resp.Entries[0].DnsNames, 1)
			s.Require().Equal("abcd.efg", resp.Entries[0].DnsNames[0])
		case 8:
			db, err := openSQLite3(dbURI)
			s.Require().NoError(err)
			s.Require().True(db.Dialect().HasIndex("registered_entries", "idx_registered_entries_parent_id"))
			s.Require().True(db.Dialect().HasIndex("registered_entries", "idx_registered_entries_spiffe_id"))
			s.Require().True(db.Dialect().HasIndex("selectors", "idx_selectors_type_value"))
		case 9:
			db, err := openSQLite3(dbURI)
			s.Require().NoError(err)
			s.Require().True(db.Dialect().HasIndex("registered_entries", "idx_registered_entries_expiry"))
		case 10:
			db, err := openSQLite3(dbURI)
			s.Require().NoError(err)
			s.Require().True(db.Dialect().HasIndex("federated_registration_entries", "idx_federated_registration_entries_registered_entry_id"))
		case 11:
			db, err := openSQLite3(dbURI)
			s.Require().NoError(err)
			s.Require().True(db.Dialect().HasColumn("migrations", "code_version"))
		case 12:
			// Ensure attested_nodes_entries gained two new columns
			db, err := openSQLite3(dbURI)
			s.Require().NoError(err)

			// Assert attested_node_entries tables gained the new columns
			s.Require().True(db.Dialect().HasColumn("attested_node_entries", "new_serial_number"))
			s.Require().True(db.Dialect().HasColumn("attested_node_entries", "new_expires_at"))

			attestedNode, err := s.ds.FetchAttestedNode(context.Background(), "spiffe://example.org/host")
			s.Require().NoError(err)

			// Assert current serial numbers and expiration time remains the same
			expectedTime, err := time.Parse(time.RFC3339, "2018-12-19T15:26:58-07:00")
			s.Require().NoError(err)
			s.Require().Equal(expectedTime.Unix(), attestedNode.CertNotAfter)
			s.Require().Equal("111", attestedNode.CertSerialNumber)

			// Assert the new fields are empty for pre-existing entries
			s.Require().Empty(attestedNode.NewCertSerialNumber)
			s.Require().Empty(attestedNode.NewCertNotAfter)
		case 13:
			s.Require().True(s.ds.db.Dialect().HasColumn("registered_entries", "revision_number"))
		case 14:
			db, err := openSQLite3(dbURI)
			s.Require().NoError(err)
			s.Require().True(db.Dialect().HasIndex("attested_node_entries", "idx_attested_node_entries_expires_at"))
		case 15:
			s.Require().True(s.ds.db.Dialect().HasColumn("registered_entries", "store_svid"))
		default:
			s.T().Fatalf("no migration test added for version %d", i)
		}
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
	entriesJSON, err := ioutil.ReadFile(filePath)
	s.Require().NoError(err)

	err = json.Unmarshal(entriesJSON, &jsonValue)
	s.Require().NoError(err)
}

func (s *PluginSuite) fetchBundle(trustDomainID string) *common.Bundle {
	bundle, err := s.ds.FetchBundle(ctx, trustDomainID)
	s.Require().NoError(err)
	return bundle
}

func (s *PluginSuite) createBundle(trustDomainID string) {
	_, err := s.ds.CreateBundle(ctx, bundleutil.BundleProtoFromRootCA(trustDomainID, s.cert))
	s.Require().NoError(err)
}

func (s *PluginSuite) createRegistrationEntry(entry *common.RegistrationEntry) *common.RegistrationEntry {
	registrationEntry, err := s.ds.CreateRegistrationEntry(ctx, entry)
	s.Require().NoError(err)
	s.Require().NotNil(registrationEntry)
	return registrationEntry
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

func (s *PluginSuite) getNodeSelectors(spiffeID string, tolerateStale bool) []*common.Selector {
	if tolerateStale && TestStaleDelay != "" {
		time.Sleep(s.staleDelay)
	}
	resp, err := s.ds.GetNodeSelectors(ctx, &datastore.GetNodeSelectorsRequest{
		SpiffeId:      spiffeID,
		TolerateStale: tolerateStale,
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().NotNil(resp.Selectors)
	s.Require().Equal(spiffeID, resp.Selectors.SpiffeId)
	return resp.Selectors.Selectors
}

func (s *PluginSuite) listNodeSelectors(req *datastore.ListNodeSelectorsRequest) *datastore.ListNodeSelectorsResponse {
	resp, err := s.ds.ListNodeSelectors(ctx, req)
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	return resp
}

func (s *PluginSuite) setNodeSelectors(spiffeID string, selectors []*common.Selector) {
	resp, err := s.ds.SetNodeSelectors(ctx, &datastore.SetNodeSelectorsRequest{
		Selectors: &datastore.NodeSelectors{
			SpiffeId:  spiffeID,
			Selectors: selectors,
		},
	})
	s.Require().NoError(err)
	s.Equal(&datastore.SetNodeSelectorsResponse{}, resp)
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
			dbPath := filepath.Join(s.dir, "test-datastore-configure.sqlite3")

			log, _ := test.NewNullLogger()

			p := New(log)
			err := p.Configure(fmt.Sprintf(`
				database_type = "sqlite3"
				log_sql = true
				connection_string = "%s"
				%s
			`, dbPath, tt.giveDBConfig))
			require.NoError(t, err)

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

func TestListRegistrationEntriesQuery(t *testing.T) {
	testCases := []struct {
		dialect     string
		paged       string
		by          []string
		supportsCTE bool
		query       string
	}{
		{
			dialect: "sqlite3",
			query: `
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id"},
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"spiffe-id"},
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "spiffe-id"},
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE parent_id = ? AND spiffe_id = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"selector-subset-one"},
			query: `
WITH listing AS (
	SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"selector-subset-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
		UNION
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"selector-exact-one"},
			query: `
WITH listing AS (
	SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"selector-exact-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "selector-subset-one"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "selector-subset-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
		INTERSECT
		SELECT e_id FROM (
			SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
			UNION
			SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
		) s_1
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "selector-exact-one"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "selector-exact-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			paged:   "no-token",
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries ORDER BY id ASC LIMIT 1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE id > ? ORDER BY id ASC LIMIT 1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"spiffe-id"},
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ? AND id > ? ORDER BY id ASC LIMIT 1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"spiffe-id", "selector-exact-one"},
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ?
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
	) s_0 WHERE e_id > ? ORDER BY e_id ASC LIMIT 1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			query: `
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id"},
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE parent_id = $1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"spiffe-id"},
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE spiffe_id = $1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "spiffe-id"},
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE parent_id = $1 AND spiffe_id = $2
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"selector-subset-one"},
			query: `
WITH listing AS (
	SELECT registered_entry_id AS e_id FROM selectors WHERE type = $1 AND value = $2
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"selector-subset-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = $1 AND value = $2
		UNION
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = $3 AND value = $4
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"selector-exact-one"},
			query: `
WITH listing AS (
	SELECT registered_entry_id AS e_id FROM selectors WHERE type = $1 AND value = $2
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"selector-exact-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = $1 AND value = $2
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = $3 AND value = $4
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "selector-subset-one"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = $1
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = $2 AND value = $3
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "selector-subset-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = $1
		INTERSECT
		SELECT e_id FROM (
			SELECT registered_entry_id AS e_id FROM selectors WHERE type = $2 AND value = $3
			UNION
			SELECT registered_entry_id AS e_id FROM selectors WHERE type = $4 AND value = $5
		) s_1
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "selector-exact-one"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = $1
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = $2 AND value = $3
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "selector-exact-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = $1
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = $2 AND value = $3
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = $4 AND value = $5
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			paged:   "no-token",
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries ORDER BY id ASC LIMIT 1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE id > $1 ORDER BY id ASC LIMIT 1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"spiffe-id"},
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE spiffe_id = $1 AND id > $2 ORDER BY id ASC LIMIT 1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"spiffe-id", "selector-exact-one"},
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE spiffe_id = $1
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = $2 AND value = $3
	) s_0 WHERE e_id > $4 ORDER BY e_id ASC LIMIT 1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"parent-id"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"spiffe-id"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ?
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"parent-id", "spiffe-id"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT id AS e_id FROM registered_entries WHERE parent_id = ? AND spiffe_id = ?
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"selector-subset-one"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"selector-subset-many"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT e_id FROM (
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
		UNION
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
	) s_0
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"selector-exact-one"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"selector-exact-many"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT DISTINCT e_id FROM (
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(e_id)
	)
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"parent-id", "selector-subset-one"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(e_id)
	)
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"parent-id", "selector-subset-many"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT e_id FROM (
			SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
			UNION
			SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
		) s_1) c_1
		USING(e_id)
	)
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"parent-id", "selector-exact-one"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(e_id)
	)
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"parent-id", "selector-exact-many"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(e_id)
		INNER JOIN
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_2
		USING(e_id)
	)
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			paged:   "no-token",
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			paged:   "with-token",
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE id > ? ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"spiffe-id"},
			paged:   "with-token",
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ? AND id > ? ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"spiffe-id", "selector-exact-one"},
			paged:   "with-token",
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT e_id FROM (
		SELECT DISTINCT e_id FROM (
			(SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ?) c_0
			INNER JOIN
			(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_1
			USING(e_id)
		) WHERE e_id > ? ORDER BY e_id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			supportsCTE: true,
			query: `
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"spiffe-id"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "spiffe-id"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE parent_id = ? AND spiffe_id = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"selector-subset-one"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"selector-subset-many"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
		UNION
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"selector-exact-one"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"selector-exact-many"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT e_id FROM (
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(e_id)
	)
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "selector-subset-one"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(e_id)
	)
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "selector-subset-many"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT e_id FROM (
			SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
			UNION
			SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
		) s_1) c_1
		USING(e_id)
	)
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "selector-exact-one"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(e_id)
	)
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "selector-exact-many"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(e_id)
		INNER JOIN
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_2
		USING(e_id)
	)
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			paged:       "no-token",
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			paged:       "with-token",
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE id > ? ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"spiffe-id"},
			paged:       "with-token",
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ? AND id > ? ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"spiffe-id", "selector-exact-one"},
			paged:       "with-token",
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT DISTINCT e_id FROM (
			(SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ?) c_0
			INNER JOIN
			(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_1
			USING(e_id)
		) WHERE e_id > ? ORDER BY e_id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"federates-with-subset-one"},
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) > 0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"federates-with-subset-many"},
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) > 0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"federates-with-exact-one"},
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(DISTINCT CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"federates-with-exact-many"},
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(DISTINCT CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "federates-with-subset-one"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
		INTERSECT
		SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) > 0
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "federates-with-subset-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
		INTERSECT
		SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) > 0
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "federates-with-exact-one"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
		INTERSECT
		SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(DISTINCT CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) = ?
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "federates-with-exact-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
		INTERSECT
		SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(DISTINCT CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) = ?
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"spiffe-id", "federates-with-exact-one"},
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ?
		INTERSECT
		SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(DISTINCT CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) = ?
	) s_0 WHERE e_id > ? ORDER BY e_id ASC LIMIT 1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"federates-with-subset-one"},
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN ($1) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(CASE WHEN B.trust_domain IN ($2) THEN B.trust_domain ELSE NULL END) > 0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"federates-with-subset-many"},
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN ($1, $2) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(CASE WHEN B.trust_domain IN ($3, $4) THEN B.trust_domain ELSE NULL END) > 0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"federates-with-exact-one"},
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN ($1) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(DISTINCT CASE WHEN B.trust_domain IN ($2) THEN B.trust_domain ELSE NULL END) = $3
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"federates-with-exact-many"},
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN ($1, $2) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(DISTINCT CASE WHEN B.trust_domain IN ($3, $4) THEN B.trust_domain ELSE NULL END) = $5
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "federates-with-subset-one"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = $1
		INTERSECT
		SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN ($2) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(CASE WHEN B.trust_domain IN ($3) THEN B.trust_domain ELSE NULL END) > 0
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "federates-with-subset-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = $1
		INTERSECT
		SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN ($2, $3) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(CASE WHEN B.trust_domain IN ($4, $5) THEN B.trust_domain ELSE NULL END) > 0
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "federates-with-exact-one"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = $1
		INTERSECT
		SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN ($2) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(DISTINCT CASE WHEN B.trust_domain IN ($3) THEN B.trust_domain ELSE NULL END) = $4
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "federates-with-exact-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = $1
		INTERSECT
		SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN ($2, $3) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(DISTINCT CASE WHEN B.trust_domain IN ($4, $5) THEN B.trust_domain ELSE NULL END) = $6
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"spiffe-id", "federates-with-exact-one"},
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE spiffe_id = $1
		INTERSECT
		SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN ($2) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(DISTINCT CASE WHEN B.trust_domain IN ($3) THEN B.trust_domain ELSE NULL END) = $4
	) s_0 WHERE e_id > $5 ORDER BY e_id ASC LIMIT 1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"federates-with-subset-one"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) > 0
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"federates-with-subset-many"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) > 0
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"federates-with-exact-one"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(DISTINCT CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) = ?
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"federates-with-exact-many"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(DISTINCT CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) = ?
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"parent-id", "federates-with-subset-one"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) > 0) c_1
		USING(e_id)
	)
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"parent-id", "federates-with-subset-many"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) > 0) c_1
		USING(e_id)
	)
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"parent-id", "federates-with-exact-one"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(DISTINCT CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) = ?) c_1
		USING(e_id)
	)
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"parent-id", "federates-with-exact-many"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(DISTINCT CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) = ?) c_1
		USING(e_id)
	)
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"spiffe-id", "federates-with-exact-one"},
			paged:   "with-token",
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT e_id FROM (
		SELECT DISTINCT e_id FROM (
			(SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ?) c_0
			INNER JOIN
			(SELECT E.id AS e_id
			FROM registered_entries E
			INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
			INNER JOIN bundles B ON B.id = FE.bundle_id
			GROUP BY E.id
			HAVING
				COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
				COUNT(DISTINCT CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) = ?) c_1
			USING(e_id)
		) WHERE e_id > ? ORDER BY e_id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"federates-with-subset-one"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) > 0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"federates-with-subset-many"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) > 0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"federates-with-exact-one"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(DISTINCT CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"federates-with-exact-many"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(DISTINCT CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "federates-with-subset-one"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) > 0) c_1
		USING(e_id)
	)
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "federates-with-subset-many"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) > 0) c_1
		USING(e_id)
	)
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "federates-with-exact-one"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(DISTINCT CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) = ?) c_1
		USING(e_id)
	)
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "federates-with-exact-many"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(DISTINCT CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) = ?) c_1
		USING(e_id)
	)
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"spiffe-id", "federates-with-exact-one"},
			paged:       "with-token",
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT DISTINCT e_id FROM (
			(SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ?) c_0
			INNER JOIN
			(SELECT E.id AS e_id
			FROM registered_entries E
			INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
			INNER JOIN bundles B ON B.id = FE.bundle_id
			GROUP BY E.id
			HAVING
				COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
				COUNT(DISTINCT CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) = ?) c_1
			USING(e_id)
		) WHERE e_id > ? ORDER BY e_id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		name := testCase.dialect + "-list-"
		if len(testCase.by) == 0 {
			name += "all"
		} else {
			name += "by-" + strings.Join(testCase.by, "-")
		}
		if testCase.paged != "" {
			name += "-paged-" + testCase.paged
		}
		if testCase.supportsCTE {
			name += "-cte"
		}
		t.Run(name, func(t *testing.T) {
			req := new(datastore.ListRegistrationEntriesRequest)
			switch testCase.paged {
			case "":
			case "no-token":
				req.Pagination = &datastore.Pagination{
					PageSize: 1,
				}
			case "with-token":
				req.Pagination = &datastore.Pagination{
					PageSize: 1,
					Token:    "2",
				}
			default:
				require.FailNow(t, "unsupported page case: %q", testCase.paged)
			}

			for _, by := range testCase.by {
				switch by {
				case "parent-id":
					req.ByParentId = &wrapperspb.StringValue{
						Value: "spiffe://parent",
					}
				case "spiffe-id":
					req.BySpiffeId = &wrapperspb.StringValue{
						Value: "spiffe://id",
					}
				case "selector-subset-one":
					req.BySelectors = &datastore.BySelectors{
						Selectors: []*common.Selector{{Type: "a", Value: "1"}},
						Match:     datastore.Subset,
					}
				case "selector-subset-many":
					req.BySelectors = &datastore.BySelectors{
						Selectors: []*common.Selector{{Type: "a", Value: "1"}, {Type: "b", Value: "2"}},
						Match:     datastore.Subset,
					}
				case "selector-exact-one":
					req.BySelectors = &datastore.BySelectors{
						Selectors: []*common.Selector{{Type: "a", Value: "1"}},
						Match:     datastore.Exact,
					}
				case "selector-exact-many":
					req.BySelectors = &datastore.BySelectors{
						Selectors: []*common.Selector{{Type: "a", Value: "1"}, {Type: "b", Value: "2"}},
						Match:     datastore.Exact,
					}
				case "federates-with-subset-one":
					req.ByFederatesWith = &datastore.ByFederatesWith{
						TrustDomains: []string{"spiffe://federates1.test"},
						Match:        datastore.Subset,
					}
				case "federates-with-subset-many":
					req.ByFederatesWith = &datastore.ByFederatesWith{
						TrustDomains: []string{"spiffe://federates1.test", "spiffe://federates2.test"},
						Match:        datastore.Subset,
					}
				case "federates-with-exact-one":
					req.ByFederatesWith = &datastore.ByFederatesWith{
						TrustDomains: []string{"spiffe://federates1.test"},
						Match:        datastore.Exact,
					}
				case "federates-with-exact-many":
					req.ByFederatesWith = &datastore.ByFederatesWith{
						TrustDomains: []string{"spiffe://federates1.test", "spiffe://federates2.test"},
						Match:        datastore.Exact,
					}
				default:
					require.FailNow(t, "unsupported by case: %q", by)
				}
			}

			query, _, err := buildListRegistrationEntriesQuery(testCase.dialect, testCase.supportsCTE, req)
			require.NoError(t, err)
			require.Equal(t, testCase.query, query)
		})
	}
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
