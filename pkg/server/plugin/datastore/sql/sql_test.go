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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/hostservices/metricsservice"
	proto_services "github.com/spiffe/spire/pkg/common/plugin/hostservices"
	ds_telemetry "github.com/spiffe/spire/pkg/common/telemetry/server/datastore"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/fakes/fakepluginmetrics"
	"github.com/spiffe/spire/test/spiretest"
	testutil "github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ctx = context.Background()

	// The following are set by the linker during integration tests to
	// run these unit tests against various SQL backends.
	TestDialect      string
	TestConnString   string
	TestROConnString string
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

	dir       string
	nextID    int
	ds        datastore.Plugin
	sqlPlugin *Plugin

	m               *fakemetrics.FakeMetrics
	expectedMetrics *fakepluginmetrics.FakePluginMetrics
}

type ListRegistrationReq struct {
	name               string
	pagination         *datastore.Pagination
	selectors          []*common.Selector
	expectedList       []*common.RegistrationEntry
	expectedPagination *datastore.Pagination
	err                string
}

func (s *PluginSuite) SetupSuite() {
	clk := clock.NewMock(s.T())

	expiredNotAfterTime, err := time.Parse(time.RFC3339, _expiredNotAfterString)
	s.Require().NoError(err)
	validNotAfterTime, err := time.Parse(time.RFC3339, _validNotAfterString)
	s.Require().NoError(err)

	caTemplate, err := testutil.NewCATemplate(clk, "foo")
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
}

func (s *PluginSuite) SetupTest() {
	s.dir = s.TempDir()
	s.ds = s.newPlugin()
}

func (s *PluginSuite) TearDownTest() {
	s.sqlPlugin.closeDB()
}

func (s *PluginSuite) newPlugin() datastore.Plugin {
	p := New()
	s.sqlPlugin = p

	var ds datastore.Plugin

	s.expectedMetrics = fakepluginmetrics.New()

	s.m = fakemetrics.New()
	metricsService := metricsservice.New(metricsservice.Config{
		Metrics: s.m,
	})

	s.LoadPlugin(builtin(p), &ds,
		spiretest.HostService(proto_services.MetricsServiceHostServiceServer(metricsService)))

	// When the test suite is executed normally, we test against sqlite3 since
	// it requires no external dependencies. The integration test framework
	// builds the test harness for a specific dialect and connection string
	switch TestDialect {
	case "":
		s.nextID++
		dbPath := filepath.Join(s.dir, fmt.Sprintf("db%d.sqlite3", s.nextID))
		_, err := ds.Configure(context.Background(), &spi.ConfigureRequest{
			Configuration: fmt.Sprintf(`
				database_type = "sqlite3"
				log_sql = true
				connection_string = "%s"
				`, dbPath),
		})
		s.Require().NoError(err)

		// assert that WAL journal mode is enabled
		jm := struct {
			JournalMode string
		}{}
		p.db.Raw("PRAGMA journal_mode").Scan(&jm)
		s.Require().Equal(jm.JournalMode, "wal")

		// assert that foreign_key support is enabled
		fk := struct {
			ForeignKeys string
		}{}
		p.db.Raw("PRAGMA foreign_keys").Scan(&fk)
		s.Require().Equal(fk.ForeignKeys, "1")
	case "mysql":
		s.T().Logf("CONN STRING: %q", TestConnString)
		s.Require().NotEmpty(TestConnString, "connection string must be set")
		wipeMySQL(s.T(), TestConnString)
		_, err := ds.Configure(context.Background(), &spi.ConfigureRequest{
			Configuration: fmt.Sprintf(`
				database_type = "mysql"
				log_sql = true
				connection_string = "%s"
				ro_connection_string = "%s"
				`, TestConnString, TestROConnString),
		})
		s.Require().NoError(err)
	case "postgres":
		s.T().Logf("CONN STRING: %q", TestConnString)
		s.Require().NotEmpty(TestConnString, "connection string must be set")
		wipePostgres(s.T(), TestConnString)
		_, err := ds.Configure(context.Background(), &spi.ConfigureRequest{
			Configuration: fmt.Sprintf(`
				database_type = "postgres"
				log_sql = true
				connection_string = "%s"
				ro_connection_string = "%s"
				`, TestConnString, TestROConnString),
		})
		s.Require().NoError(err)
	default:
		s.Require().FailNowf("Unsupported external test dialect %q", TestDialect)
	}

	return ds
}

func (s *PluginSuite) TestInvalidPluginConfiguration() {
	_, err := s.ds.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: `
		database_type = "wrong"
		connection_string = "bad"
		`,
	})
	s.RequireErrorContains(err, "datastore-sql: unsupported database_type: wrong")
}

func (s *PluginSuite) TestInvalidMySQLConfiguration() {
	_, err := s.ds.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: `
		database_type = "mysql"
		connection_string = "username:@tcp(127.0.0.1)/spire_test"
		`,
	})
	s.RequireErrorContains(err, "datastore-sql: invalid mysql config: missing parseTime=true param in connection_string")

	_, roErr := s.ds.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: `
		database_type = "mysql"
		ro_connection_string = "username:@tcp(127.0.0.1)/spire_test"
		`,
	})
	s.RequireErrorContains(roErr, "rpc error: code = Unknown desc = connection_string must be set")

	_, error := s.ds.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: `
		database_type = "mysql"
		`,
	})
	s.RequireErrorContains(error, "rpc error: code = Unknown desc = connection_string must be set")
}

func (s *PluginSuite) TestBundleCRUD() {
	bundle := bundleutil.BundleProtoFromRootCA("spiffe://foo", s.cert)

	// fetch non-existent
	expectedCallCounter := ds_telemetry.StartFetchBundleCall(s.expectedMetrics)
	fresp, err := s.ds.FetchBundle(ctx, &datastore.FetchBundleRequest{TrustDomainId: "spiffe://foo"})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Require().NotNil(fresp)
	s.Require().Nil(fresp.Bundle)

	// update non-existent
	expectedCallCounter = ds_telemetry.StartUpdateBundleCall(s.expectedMetrics)
	_, err = s.ds.UpdateBundle(ctx, &datastore.UpdateBundleRequest{Bundle: bundle})
	expectedErr := status.Error(codes.NotFound, _notFoundErrMsg)
	expectedCallCounter.Done(&expectedErr)
	s.RequireGRPCStatus(err, codes.NotFound, _notFoundErrMsg)

	// delete non-existent
	expectedCallCounter = ds_telemetry.StartDeleteBundleCall(s.expectedMetrics)
	_, err = s.ds.DeleteBundle(ctx, &datastore.DeleteBundleRequest{TrustDomainId: "spiffe://foo"})
	expectedErr = status.Error(codes.NotFound, _notFoundErrMsg)
	expectedCallCounter.Done(&expectedErr)
	s.RequireGRPCStatus(err, codes.NotFound, _notFoundErrMsg)

	// create
	expectedCallCounter = ds_telemetry.StartCreateBundleCall(s.expectedMetrics)
	_, err = s.ds.CreateBundle(ctx, &datastore.CreateBundleRequest{
		Bundle: bundle,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)

	// fetch
	expectedCallCounter = ds_telemetry.StartFetchBundleCall(s.expectedMetrics)
	fresp, err = s.ds.FetchBundle(ctx, &datastore.FetchBundleRequest{TrustDomainId: "spiffe://foo"})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.AssertProtoEqual(bundle, fresp.Bundle)

	// fetch (with denormalized id)
	expectedCallCounter = ds_telemetry.StartFetchBundleCall(s.expectedMetrics)
	fresp, err = s.ds.FetchBundle(ctx, &datastore.FetchBundleRequest{TrustDomainId: "spiffe://fOO"})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.AssertProtoEqual(bundle, fresp.Bundle)

	// list
	expectedCallCounter = ds_telemetry.StartListBundleCall(s.expectedMetrics)
	lresp, err := s.ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Equal(1, len(lresp.Bundles))
	s.AssertProtoEqual(bundle, lresp.Bundles[0])

	bundle2 := bundleutil.BundleProtoFromRootCA(bundle.TrustDomainId, s.cacert)
	appendedBundle := bundleutil.BundleProtoFromRootCAs(bundle.TrustDomainId,
		[]*x509.Certificate{s.cert, s.cacert})

	// append
	expectedCallCounter = ds_telemetry.StartAppendBundleCall(s.expectedMetrics)
	aresp, err := s.ds.AppendBundle(ctx, &datastore.AppendBundleRequest{
		Bundle: bundle2,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Require().NotNil(aresp.Bundle)
	s.AssertProtoEqual(appendedBundle, aresp.Bundle)

	// append identical
	expectedCallCounter = ds_telemetry.StartAppendBundleCall(s.expectedMetrics)
	aresp, err = s.ds.AppendBundle(ctx, &datastore.AppendBundleRequest{
		Bundle: bundle2,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Require().NotNil(aresp.Bundle)
	s.AssertProtoEqual(appendedBundle, aresp.Bundle)

	// append on a new bundle
	bundle3 := bundleutil.BundleProtoFromRootCA("spiffe://bar", s.cacert)
	expectedCallCounter = ds_telemetry.StartAppendBundleCall(s.expectedMetrics)
	anresp, err := s.ds.AppendBundle(ctx, &datastore.AppendBundleRequest{
		Bundle: bundle3,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.AssertProtoEqual(bundle3, anresp.Bundle)

	// update
	expectedCallCounter = ds_telemetry.StartUpdateBundleCall(s.expectedMetrics)
	uresp, err := s.ds.UpdateBundle(ctx, &datastore.UpdateBundleRequest{
		Bundle: bundle2,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.AssertProtoEqual(bundle2, uresp.Bundle)

	expectedCallCounter = ds_telemetry.StartListBundleCall(s.expectedMetrics)
	lresp, err = s.ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	assertBundlesEqual(s.T(), []*common.Bundle{bundle2, bundle3}, lresp.Bundles)

	// delete
	expectedCallCounter = ds_telemetry.StartDeleteBundleCall(s.expectedMetrics)
	dresp, err := s.ds.DeleteBundle(ctx, &datastore.DeleteBundleRequest{
		TrustDomainId: bundle.TrustDomainId,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.AssertProtoEqual(bundle2, dresp.Bundle)

	expectedCallCounter = ds_telemetry.StartListBundleCall(s.expectedMetrics)
	lresp, err = s.ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Equal(1, len(lresp.Bundles))
	s.AssertProtoEqual(bundle3, lresp.Bundles[0])

	// delete (with denormalized id)
	expectedCallCounter = ds_telemetry.StartDeleteBundleCall(s.expectedMetrics)
	dresp, err = s.ds.DeleteBundle(ctx, &datastore.DeleteBundleRequest{
		TrustDomainId: "spiffe://bAR",
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.AssertProtoEqual(bundle3, dresp.Bundle)

	expectedCallCounter = ds_telemetry.StartListBundleCall(s.expectedMetrics)
	lresp, err = s.ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Empty(lresp.Bundles)

	s.Require().Equal(s.expectedMetrics.AllMetrics(), s.m.AllMetrics())
}

func (s *PluginSuite) TestSetBundle() {
	// create a couple of bundles for tests. the contents don't really matter
	// as long as they are for the same trust domain but have different contents.
	bundle := bundleutil.BundleProtoFromRootCA("spiffe://foo", s.cert)
	bundle2 := bundleutil.BundleProtoFromRootCA("spiffe://foo", s.cacert)

	// ensure the bundle does not exist (it shouldn't)
	s.Require().Nil(s.fetchBundle("spiffe://foo"))

	// set the bundle and make sure it is created
	expectedCallCounter := ds_telemetry.StartSetBundleCall(s.expectedMetrics)
	_, err := s.ds.SetBundle(ctx, &datastore.SetBundleRequest{
		Bundle: bundle,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.RequireProtoEqual(bundle, s.fetchBundle("spiffe://foo"))

	// set the bundle and make sure it is updated
	expectedCallCounter = ds_telemetry.StartSetBundleCall(s.expectedMetrics)
	_, err = s.ds.SetBundle(ctx, &datastore.SetBundleRequest{
		Bundle: bundle2,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.RequireProtoEqual(bundle2, s.fetchBundle("spiffe://foo"))

	s.Require().Equal(s.expectedMetrics.AllMetrics(), s.m.AllMetrics())
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
	expectedCallCounter := ds_telemetry.StartCreateBundleCall(s.expectedMetrics)
	_, err = s.ds.CreateBundle(ctx, &datastore.CreateBundleRequest{Bundle: bundle})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)

	// Prune
	// prune non existent bundle should not return error, no bundle to prune
	expiration := time.Now().Unix()
	expectedCallCounter = ds_telemetry.StartPruneBundleCall(s.expectedMetrics)
	presp, err := s.ds.PruneBundle(ctx, &datastore.PruneBundleRequest{
		TrustDomainId: "spiffe://notexistent",
		ExpiresBefore: expiration,
	})
	expectedCallCounter.Done(nil)
	s.NoError(err)
	s.AssertProtoEqual(presp, &datastore.PruneBundleResponse{})

	// prune fails if internal prune bundle fails. For instance, if all certs are expired
	expiration = time.Now().Unix()
	expectedCallCounter = ds_telemetry.StartPruneBundleCall(s.expectedMetrics)
	presp, err = s.ds.PruneBundle(ctx, &datastore.PruneBundleRequest{
		TrustDomainId: bundle.TrustDomainId,
		ExpiresBefore: expiration,
	})
	expectedError := errors.New("prune failed: would prune all certificates")
	expectedCallCounter.Done(&expectedError)
	s.Error(err, expectedError.Error())
	s.Nil(presp)

	// prune should remove expired certs
	expectedCallCounter = ds_telemetry.StartPruneBundleCall(s.expectedMetrics)
	presp, err = s.ds.PruneBundle(ctx, &datastore.PruneBundleRequest{
		TrustDomainId: bundle.TrustDomainId,
		ExpiresBefore: middleTime.Unix(),
	})
	expectedCallCounter.Done(nil)
	s.NoError(err)
	s.NotNil(presp)
	s.True(presp.BundleChanged)

	// Fetch and verify pruned bundle is the expected
	expectedPrunedBundle := bundleutil.BundleProtoFromRootCAs("spiffe://foo", []*x509.Certificate{s.cert})
	expectedPrunedBundle.JwtSigningKeys = []*common.PublicKey{{NotAfter: nonExpiredKeyTime.Unix()}}
	expectedCallCounter = ds_telemetry.StartFetchBundleCall(s.expectedMetrics)
	fresp, err := s.ds.FetchBundle(ctx, &datastore.FetchBundleRequest{TrustDomainId: "spiffe://foo"})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.AssertProtoEqual(expectedPrunedBundle, fresp.Bundle)

	s.Require().Equal(s.expectedMetrics.AllMetrics(), s.m.AllMetrics())
}

func (s *PluginSuite) TestCreateAttestedNode() {
	node := &common.AttestedNode{
		SpiffeId:            "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}

	expectedCallCounter := ds_telemetry.StartCreateNodeCall(s.expectedMetrics)
	cresp, err := s.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{Node: node})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.AssertProtoEqual(node, cresp.Node)

	expectedCallCounter = ds_telemetry.StartFetchNodeCall(s.expectedMetrics)
	fresp, err := s.ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{SpiffeId: node.SpiffeId})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.AssertProtoEqual(node, fresp.Node)

	expiration := time.Now().Unix()
	expectedCallCounter = ds_telemetry.StartListNodeCall(s.expectedMetrics)
	sresp, err := s.ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{
		ByExpiresBefore: &wrappers.Int64Value{
			Value: expiration,
		},
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Empty(sresp.Nodes)

	s.Require().Equal(s.expectedMetrics.AllMetrics(), s.m.AllMetrics())
}

func (s *PluginSuite) TestFetchAttestedNodeMissing() {
	expectedCallCounter := ds_telemetry.StartFetchNodeCall(s.expectedMetrics)
	fresp, err := s.ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{SpiffeId: "missing"})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Require().Nil(fresp.Node)

	s.Require().Equal(s.expectedMetrics.AllMetrics(), s.m.AllMetrics())
}

func (s *PluginSuite) TestFetchStaleNodes() {
	efuture := &common.AttestedNode{
		SpiffeId:            "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}

	epast := &common.AttestedNode{
		SpiffeId:            "bar",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "deadbeef",
		CertNotAfter:        time.Now().Add(-time.Hour).Unix(),
	}

	expectedCallCounter := ds_telemetry.StartCreateNodeCall(s.expectedMetrics)
	_, err := s.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{Node: efuture})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)

	expectedCallCounter = ds_telemetry.StartCreateNodeCall(s.expectedMetrics)
	_, err = s.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{Node: epast})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)

	expiration := time.Now().Unix()
	expectedCallCounter = ds_telemetry.StartListNodeCall(s.expectedMetrics)
	sresp, err := s.ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{
		ByExpiresBefore: &wrappers.Int64Value{
			Value: expiration,
		},
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.RequireProtoListEqual([]*common.AttestedNode{epast}, sresp.Nodes)

	s.Require().Equal(s.expectedMetrics.AllMetrics(), s.m.AllMetrics())
}

func (s *PluginSuite) TestFetchAttestedNodesWithPagination() {
	// Create all necessary nodes
	aNode1 := &common.AttestedNode{
		SpiffeId:            "node1",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(-time.Hour).Unix(),
	}

	aNode2 := &common.AttestedNode{
		SpiffeId:            "node2",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "deadbeef",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}

	aNode3 := &common.AttestedNode{
		SpiffeId:            "node3",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(-time.Hour).Unix(),
	}

	aNode4 := &common.AttestedNode{
		SpiffeId:            "node4",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(-time.Hour).Unix(),
	}

	_, err := s.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{Node: aNode1})
	s.Require().NoError(err)

	_, err = s.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{Node: aNode2})
	s.Require().NoError(err)

	_, err = s.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{Node: aNode3})
	s.Require().NoError(err)

	_, err = s.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{Node: aNode4})
	s.Require().NoError(err)

	tests := []struct {
		name               string
		pagination         *datastore.Pagination
		byExpiresBefore    *wrappers.Int64Value
		expectedList       []*common.AttestedNode
		expectedPagination *datastore.Pagination
		expectedErr        string
	}{
		{
			name: "pagination_without_token",
			pagination: &datastore.Pagination{
				PageSize: 2,
			},
			expectedList: []*common.AttestedNode{aNode1, aNode2},
			expectedPagination: &datastore.Pagination{
				Token:    "2",
				PageSize: 2,
			},
		},
		{
			name: "pagination_not_null_but_page_size_is_zero",
			pagination: &datastore.Pagination{
				Token:    "0",
				PageSize: 0,
			},
			expectedErr: "rpc error: code = InvalidArgument desc = cannot paginate with pagesize = 0",
		},
		{
			name: "get_all_nodes_first_page",
			pagination: &datastore.Pagination{
				Token:    "0",
				PageSize: 2,
			},
			expectedList: []*common.AttestedNode{aNode1, aNode2},
			expectedPagination: &datastore.Pagination{
				Token:    "2",
				PageSize: 2,
			},
		},
		{
			name: "get_all_nodes_second_page",
			pagination: &datastore.Pagination{
				Token:    "2",
				PageSize: 2,
			},
			expectedList: []*common.AttestedNode{aNode3, aNode4},
			expectedPagination: &datastore.Pagination{
				Token:    "4",
				PageSize: 2,
			},
		},
		{
			name:         "get_all_nodes_third_page_no_results",
			expectedList: []*common.AttestedNode{},
			pagination: &datastore.Pagination{
				Token:    "4",
				PageSize: 2,
			},
			expectedPagination: &datastore.Pagination{
				PageSize: 2,
			},
		},
		{
			name: "get_nodes_by_expire_before_get_only_page_first_page",
			pagination: &datastore.Pagination{
				Token:    "0",
				PageSize: 2,
			},
			byExpiresBefore: &wrappers.Int64Value{
				Value: time.Now().Unix(),
			},
			expectedList: []*common.AttestedNode{aNode1, aNode3},
			expectedPagination: &datastore.Pagination{
				Token:    "3",
				PageSize: 2,
			},
		},
		{
			name: "get_nodes_by_expire_before_get_only_page_second_page",
			pagination: &datastore.Pagination{
				Token:    "3",
				PageSize: 2,
			},
			byExpiresBefore: &wrappers.Int64Value{
				Value: time.Now().Unix(),
			},
			expectedList: []*common.AttestedNode{aNode4},
			expectedPagination: &datastore.Pagination{
				Token:    "4",
				PageSize: 2,
			},
		},
		{
			name: "get_nodes_by_expire_before_get_only_page_third_page_no_results",
			pagination: &datastore.Pagination{
				Token:    "4",
				PageSize: 2,
			},
			byExpiresBefore: &wrappers.Int64Value{
				Value: time.Now().Unix(),
			},
			expectedList: []*common.AttestedNode{},
			expectedPagination: &datastore.Pagination{
				PageSize: 2,
			},
		},
	}
	for _, test := range tests {
		test := test
		s.T().Run(test.name, func(t *testing.T) {
			resp, err := s.ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{
				ByExpiresBefore: test.byExpiresBefore,
				Pagination:      test.pagination,
			})
			if test.expectedErr != "" {
				require.EqualError(t, err, test.expectedErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)

			expectedResponse := &datastore.ListAttestedNodesResponse{
				Nodes:      test.expectedList,
				Pagination: test.expectedPagination,
			}
			spiretest.RequireProtoEqual(t, expectedResponse, resp)
		})
	}

	// with invalid token
	resp, err := s.ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{
		Pagination: &datastore.Pagination{
			Token:    "invalid int",
			PageSize: 10,
		},
	})
	s.Require().Nil(resp)
	s.Require().Error(err, "could not parse token 'invalid int'")
}

func (s *PluginSuite) TestUpdateAttestedNode() {
	node := &common.AttestedNode{
		SpiffeId:            "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}

	userial := "deadbeef"
	uexpires := time.Now().Add(time.Hour * 2).Unix()

	// update non-existing attested node
	expectedCallCounter := ds_telemetry.StartUpdateNodeCall(s.expectedMetrics)
	_, err := s.ds.UpdateAttestedNode(ctx, &datastore.UpdateAttestedNodeRequest{
		SpiffeId:         node.SpiffeId,
		CertSerialNumber: userial,
		CertNotAfter:     uexpires,
	})
	expectedError := status.Error(codes.NotFound, _notFoundErrMsg)
	expectedCallCounter.Done(&expectedError)
	s.RequireGRPCStatus(err, codes.NotFound, _notFoundErrMsg)

	expectedCallCounter = ds_telemetry.StartCreateNodeCall(s.expectedMetrics)
	_, err = s.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{Node: node})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)

	expectedCallCounter = ds_telemetry.StartUpdateNodeCall(s.expectedMetrics)
	uresp, err := s.ds.UpdateAttestedNode(ctx, &datastore.UpdateAttestedNodeRequest{
		SpiffeId:         node.SpiffeId,
		CertSerialNumber: userial,
		CertNotAfter:     uexpires,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)

	unode := uresp.Node
	s.Require().NotNil(unode)

	s.Equal(node.SpiffeId, unode.SpiffeId)
	s.Equal(node.AttestationDataType, unode.AttestationDataType)
	s.Equal(userial, unode.CertSerialNumber)
	s.Equal(uexpires, unode.CertNotAfter)

	expectedCallCounter = ds_telemetry.StartFetchNodeCall(s.expectedMetrics)
	fresp, err := s.ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{SpiffeId: node.SpiffeId})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)

	fnode := fresp.Node
	s.Require().NotNil(fnode)

	s.Equal(node.SpiffeId, fnode.SpiffeId)
	s.Equal(node.AttestationDataType, fnode.AttestationDataType)
	s.Equal(userial, fnode.CertSerialNumber)
	s.Equal(uexpires, fnode.CertNotAfter)

	s.Require().Equal(s.expectedMetrics.AllMetrics(), s.m.AllMetrics())
}

func (s *PluginSuite) TestDeleteAttestedNode() {
	entry := &common.AttestedNode{
		SpiffeId:            "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}

	// delete it before it exists
	expectedCallCounter := ds_telemetry.StartDeleteNodeCall(s.expectedMetrics)
	_, err := s.ds.DeleteAttestedNode(ctx, &datastore.DeleteAttestedNodeRequest{SpiffeId: entry.SpiffeId})
	expectedError := status.Error(codes.NotFound, _notFoundErrMsg)
	expectedCallCounter.Done(&expectedError)
	s.RequireGRPCStatus(err, codes.NotFound, _notFoundErrMsg)

	expectedCallCounter = ds_telemetry.StartCreateNodeCall(s.expectedMetrics)
	_, err = s.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{Node: entry})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)

	expectedCallCounter = ds_telemetry.StartDeleteNodeCall(s.expectedMetrics)
	dresp, err := s.ds.DeleteAttestedNode(ctx, &datastore.DeleteAttestedNodeRequest{SpiffeId: entry.SpiffeId})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.AssertProtoEqual(entry, dresp.Node)

	expectedCallCounter = ds_telemetry.StartFetchNodeCall(s.expectedMetrics)
	fresp, err := s.ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{SpiffeId: entry.SpiffeId})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Nil(fresp.Node)

	s.Require().Equal(s.expectedMetrics.AllMetrics(), s.m.AllMetrics())
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

	s.Require().Equal(s.expectedMetrics.AllMetrics(), s.m.AllMetrics())
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
		expectedCallCounter := ds_telemetry.StartCreateRegistrationCall(s.expectedMetrics)
		resp, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{Entry: validRegistrationEntry})
		expectedCallCounter.Done(nil)
		s.Require().NoError(err)
		s.NotNil(resp)
		s.Require().NotNil(resp.Entry)
		s.NotEmpty(resp.Entry.EntryId)
		resp.Entry.EntryId = ""
		s.RequireProtoEqual(resp.Entry, validRegistrationEntry)
	}

	s.Require().Equal(s.expectedMetrics.AllMetrics(), s.m.AllMetrics())
}

func (s *PluginSuite) TestCreateInvalidRegistrationEntry() {
	var invalidRegistrationEntries []*common.RegistrationEntry
	s.getTestDataFromJSONFile(filepath.Join("testdata", "invalid_registration_entries.json"), &invalidRegistrationEntries)

	for _, invalidRegistrationEntry := range invalidRegistrationEntries {
		expectedCallCounter := ds_telemetry.StartCreateRegistrationCall(s.expectedMetrics)
		createRegistrationEntryResponse, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{Entry: invalidRegistrationEntry})
		expectedCallCounter.Done(&err)
		s.Require().Error(err)
		s.Require().Nil(createRegistrationEntryResponse)
	}

	s.Require().Equal(s.expectedMetrics.AllMetrics(), s.m.AllMetrics())

	// TODO: Check that no entries have been created
}

func (s *PluginSuite) TestFetchRegistrationEntry() {
	registeredEntry := &common.RegistrationEntry{
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

	expectedCallCounter := ds_telemetry.StartCreateRegistrationCall(s.expectedMetrics)
	createRegistrationEntryResponse, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{Entry: registeredEntry})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Require().NotNil(createRegistrationEntryResponse)
	createdEntry := createRegistrationEntryResponse.Entry

	expectedCallCounter = ds_telemetry.StartFetchRegistrationCall(s.expectedMetrics)
	fetchRegistrationEntryResponse, err := s.ds.FetchRegistrationEntry(ctx, &datastore.FetchRegistrationEntryRequest{EntryId: createdEntry.EntryId})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Require().NotNil(fetchRegistrationEntryResponse)
	s.RequireProtoEqual(createdEntry, fetchRegistrationEntryResponse.Entry)

	s.Require().Equal(s.expectedMetrics.AllMetrics(), s.m.AllMetrics())
}

func (s *PluginSuite) TestPruneRegistrationEntries() {
	now := time.Now().Unix()
	registeredEntry := &common.RegistrationEntry{
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

	expectedCallCounter := ds_telemetry.StartCreateRegistrationCall(s.expectedMetrics)
	createRegistrationEntryResponse, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{Entry: registeredEntry})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Require().NotNil(createRegistrationEntryResponse)
	createdEntry := createRegistrationEntryResponse.Entry

	// Ensure we don't prune valid entries, wind clock back 10s
	expectedCallCounter = ds_telemetry.StartPruneRegistrationCall(s.expectedMetrics)
	_, err = s.ds.PruneRegistrationEntries(ctx, &datastore.PruneRegistrationEntriesRequest{
		ExpiresBefore: now - 10,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)

	expectedCallCounter = ds_telemetry.StartFetchRegistrationCall(s.expectedMetrics)
	fetchRegistrationEntryResponse, err := s.ds.FetchRegistrationEntry(ctx, &datastore.FetchRegistrationEntryRequest{EntryId: createdEntry.EntryId})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Require().NotNil(fetchRegistrationEntryResponse)
	s.Equal(createdEntry, fetchRegistrationEntryResponse.Entry)

	// Ensure we don't prune on the exact ExpiresBefore
	expectedCallCounter = ds_telemetry.StartPruneRegistrationCall(s.expectedMetrics)
	_, err = s.ds.PruneRegistrationEntries(ctx, &datastore.PruneRegistrationEntriesRequest{
		ExpiresBefore: now,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)

	expectedCallCounter = ds_telemetry.StartFetchRegistrationCall(s.expectedMetrics)
	fetchRegistrationEntryResponse, err = s.ds.FetchRegistrationEntry(ctx, &datastore.FetchRegistrationEntryRequest{EntryId: createdEntry.EntryId})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Require().NotNil(fetchRegistrationEntryResponse)
	s.Equal(createdEntry, fetchRegistrationEntryResponse.Entry)

	// Ensure we prune old entries
	expectedCallCounter = ds_telemetry.StartPruneRegistrationCall(s.expectedMetrics)
	_, err = s.ds.PruneRegistrationEntries(ctx, &datastore.PruneRegistrationEntriesRequest{
		ExpiresBefore: now + 10,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)

	expectedCallCounter = ds_telemetry.StartFetchRegistrationCall(s.expectedMetrics)
	fetchRegistrationEntryResponse, err = s.ds.FetchRegistrationEntry(ctx, &datastore.FetchRegistrationEntryRequest{EntryId: createdEntry.EntryId})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Nil(fetchRegistrationEntryResponse.Entry)

	s.Require().Equal(s.expectedMetrics.AllMetrics(), s.m.AllMetrics())
}

func (s *PluginSuite) TestFetchInexistentRegistrationEntry() {
	expectedCallCounter := ds_telemetry.StartFetchRegistrationCall(s.expectedMetrics)
	fetchRegistrationEntryResponse, err := s.ds.FetchRegistrationEntry(ctx, &datastore.FetchRegistrationEntryRequest{EntryId: "INEXISTENT"})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Require().Nil(fetchRegistrationEntryResponse.Entry)

	s.Require().Equal(s.expectedMetrics.AllMetrics(), s.m.AllMetrics())
}

func (s *PluginSuite) TestListRegistrationEntries() {
	entry1 := s.createRegistrationEntry(&common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
			{Type: "Type2", Value: "Value2"},
			{Type: "Type3", Value: "Value3"},
		},
		SpiffeId: "spiffe://example.org/foo",
		ParentId: "spiffe://example.org/bar",
		Ttl:      1,
		Admin:    true,
	})

	entry2 := s.createRegistrationEntry(&common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type3", Value: "Value3"},
			{Type: "Type4", Value: "Value4"},
			{Type: "Type5", Value: "Value5"},
		},
		SpiffeId:   "spiffe://example.org/baz",
		ParentId:   "spiffe://example.org/bat",
		Ttl:        2,
		Downstream: true,
	})

	expectedCallCounter := ds_telemetry.StartListRegistrationCall(s.expectedMetrics)
	resp, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Require().NotNil(resp)

	expectedResponse := &datastore.ListRegistrationEntriesResponse{
		Entries: []*common.RegistrationEntry{entry2, entry1},
	}
	util.SortRegistrationEntries(expectedResponse.Entries)
	util.SortRegistrationEntries(resp.Entries)
	s.Equal(expectedResponse, resp)

	s.Require().Equal(s.expectedMetrics.AllMetrics(), s.m.AllMetrics())
}

func (s *PluginSuite) TestListRegistrationEntriesWithPagination() {
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

	entry2 := s.createRegistrationEntry(&common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type3", Value: "Value3"},
			{Type: "Type4", Value: "Value4"},
			{Type: "Type5", Value: "Value5"},
		},
		SpiffeId: "spiffe://example.org/baz",
		ParentId: "spiffe://example.org/bat",
		Ttl:      2,
	})

	entry3 := s.createRegistrationEntry(&common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
			{Type: "Type2", Value: "Value2"},
			{Type: "Type3", Value: "Value3"},
		},
		SpiffeId: "spiffe://example.org/tez",
		ParentId: "spiffe://example.org/taz",
		Ttl:      2,
	})

	selectors := []*common.Selector{
		{Type: "Type1", Value: "Value1"},
		{Type: "Type2", Value: "Value2"},
		{Type: "Type3", Value: "Value3"},
	}

	tests := []ListRegistrationReq{
		{
			name: "pagination_without_token",
			pagination: &datastore.Pagination{
				PageSize: 2,
			},
			expectedList: []*common.RegistrationEntry{entry2, entry1},
			expectedPagination: &datastore.Pagination{
				Token:    "2",
				PageSize: 2,
			},
		},
		{
			name: "pagination_not_null_but_page_size_is_zero",
			pagination: &datastore.Pagination{
				Token:    "0",
				PageSize: 0,
			},
			err: "rpc error: code = InvalidArgument desc = cannot paginate with pagesize = 0",
		},
		{
			name: "get_all_entries_first_page",
			pagination: &datastore.Pagination{
				Token:    "0",
				PageSize: 2,
			},
			expectedList: []*common.RegistrationEntry{entry2, entry1},
			expectedPagination: &datastore.Pagination{
				Token:    "2",
				PageSize: 2,
			},
		},
		{
			name: "get_all_entries_second_page",
			pagination: &datastore.Pagination{
				Token:    "2",
				PageSize: 2,
			},
			expectedList: []*common.RegistrationEntry{entry3},
			expectedPagination: &datastore.Pagination{
				Token:    "3",
				PageSize: 2,
			},
		},
		{
			name: "get_all_entries_third_page_no_results",
			pagination: &datastore.Pagination{
				Token:    "3",
				PageSize: 2,
			},
			expectedPagination: &datastore.Pagination{
				PageSize: 2,
			},
		},
		{
			name: "get_entries_by_selector_get_only_page_first_page",
			pagination: &datastore.Pagination{
				Token:    "0",
				PageSize: 2,
			},
			selectors:    selectors,
			expectedList: []*common.RegistrationEntry{entry1, entry3},
			expectedPagination: &datastore.Pagination{
				Token:    "3",
				PageSize: 2,
			},
		},
		{
			name: "get_entries_by_selector_get_only_page_second_page_no_results",
			pagination: &datastore.Pagination{
				Token:    "3",
				PageSize: 2,
			},
			selectors: selectors,
			expectedPagination: &datastore.Pagination{
				PageSize: 2,
			},
		},
		{
			name: "get_entries_by_selector_first_page",
			pagination: &datastore.Pagination{
				Token:    "0",
				PageSize: 1,
			},
			selectors:    selectors,
			expectedList: []*common.RegistrationEntry{entry1},
			expectedPagination: &datastore.Pagination{
				Token:    "1",
				PageSize: 1,
			},
		},
		{
			name: "get_entries_by_selector_second_page",
			pagination: &datastore.Pagination{
				Token:    "1",
				PageSize: 1,
			},
			selectors:    selectors,
			expectedList: []*common.RegistrationEntry{entry3},
			expectedPagination: &datastore.Pagination{
				Token:    "3",
				PageSize: 1,
			},
		},
		{
			name: "get_entries_by_selector_third_page_no_results",
			pagination: &datastore.Pagination{
				Token:    "3",
				PageSize: 1,
			},
			selectors: selectors,
			expectedPagination: &datastore.Pagination{
				PageSize: 1,
			},
		},
	}

	s.listRegistrationEntries(tests, true)
	s.listRegistrationEntries(tests, false)

	// with invalid token
	resp, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		Pagination: &datastore.Pagination{
			Token:    "invalid int",
			PageSize: 10,
		},
	})
	s.Require().Nil(resp)
	s.Require().Error(err, "could not parse token 'invalid int'")
}

func (s *PluginSuite) listRegistrationEntries(tests []ListRegistrationReq, tolerateStale bool) {
	for _, test := range tests {
		test := test
		s.T().Run(test.name, func(t *testing.T) {
			var bySelectors *datastore.BySelectors
			if test.selectors != nil {
				bySelectors = &datastore.BySelectors{
					Selectors: test.selectors,
					Match:     datastore.BySelectors_MATCH_EXACT,
				}
			}
			resp, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				BySelectors:   bySelectors,
				Pagination:    test.pagination,
				TolerateStale: tolerateStale,
			})
			if test.err != "" {
				require.EqualError(t, err, test.err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)

			expectedResponse := &datastore.ListRegistrationEntriesResponse{
				Entries:    test.expectedList,
				Pagination: test.expectedPagination,
			}
			util.SortRegistrationEntries(expectedResponse.Entries)
			util.SortRegistrationEntries(resp.Entries)
			require.Equal(t, expectedResponse, resp)
		})
	}
}

func (s *PluginSuite) TestListRegistrationEntriesAgainstMultipleCriteria() {
	entry := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId: "spiffe://example.org/P1",
		SpiffeId: "spiffe://example.org/S1",
		Selectors: []*common.Selector{
			{Type: "T1", Value: "V1"},
		},
	})

	// shares a parent ID
	s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId: "spiffe://example.org/P1",
		SpiffeId: "spiffe://example.org/S2",
		Selectors: []*common.Selector{
			{Type: "T2", Value: "V2"},
		},
	})

	// shares a spiffe ID
	s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId: "spiffe://example.org/P3",
		SpiffeId: "spiffe://example.org/S1",
		Selectors: []*common.Selector{
			{Type: "T3", Value: "V3"},
		},
	})

	// shares selectors
	s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId: "spiffe://example.org/P4",
		SpiffeId: "spiffe://example.org/S4",
		Selectors: []*common.Selector{
			{Type: "T1", Value: "V1"},
		},
	})

	resp, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		ByParentId: &wrappers.StringValue{
			Value: "spiffe://example.org/P1",
		},
		BySpiffeId: &wrappers.StringValue{
			Value: "spiffe://example.org/S1",
		},
		BySelectors: &datastore.BySelectors{
			Selectors: []*common.Selector{
				{Type: "T1", Value: "V1"},
			},
			Match: datastore.BySelectors_MATCH_EXACT,
		},
	})

	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.RequireProtoListEqual([]*common.RegistrationEntry{entry}, resp.Entries)
}

func (s *PluginSuite) TestListRegistrationEntriesWhenCruftRowsExist() {
	_, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{
		Entry: &common.RegistrationEntry{
			Selectors: []*common.Selector{
				{Type: "TYPE", Value: "VALUE"},
			},
			SpiffeId: "SpiffeId",
			ParentId: "ParentId",
			DnsNames: []string{
				"abcd.efg",
				"somehost",
			},
		},
	})
	s.Require().NoError(err)

	// This is gross. Since the bug that left selectors around has been fixed
	// (#1191), I'm not sure how else to test this other than just sneaking in
	// there and removing the registered_entries row.
	res, err := s.sqlPlugin.db.raw.Exec("DELETE FROM registered_entries")
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

	expectedCallCounter := ds_telemetry.StartUpdateRegistrationCall(s.expectedMetrics)
	updateRegistrationEntryResponse, err := s.ds.UpdateRegistrationEntry(ctx, &datastore.UpdateRegistrationEntryRequest{
		Entry: entry,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Require().NotNil(updateRegistrationEntryResponse)

	expectedCallCounter = ds_telemetry.StartFetchRegistrationCall(s.expectedMetrics)
	fetchRegistrationEntryResponse, err := s.ds.FetchRegistrationEntry(ctx, &datastore.FetchRegistrationEntryRequest{EntryId: entry.EntryId})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Require().NotNil(fetchRegistrationEntryResponse)
	s.Require().NotNil(fetchRegistrationEntryResponse.Entry)
	s.RequireProtoEqual(entry, fetchRegistrationEntryResponse.Entry)

	entry.EntryId = "badid"
	expectedCallCounter = ds_telemetry.StartUpdateRegistrationCall(s.expectedMetrics)
	_, err = s.ds.UpdateRegistrationEntry(ctx, &datastore.UpdateRegistrationEntryRequest{
		Entry: entry,
	})
	expectedError := status.Error(codes.NotFound, _notFoundErrMsg)
	expectedCallCounter.Done(&expectedError)
	s.RequireGRPCStatus(err, codes.NotFound, _notFoundErrMsg)

	s.Require().Equal(s.expectedMetrics.AllMetrics(), s.m.AllMetrics())
}

func (s *PluginSuite) TestDeleteRegistrationEntry() {
	// delete non-existing
	expectedCallCounter := ds_telemetry.StartDeleteRegistrationCall(s.expectedMetrics)
	_, err := s.ds.DeleteRegistrationEntry(ctx, &datastore.DeleteRegistrationEntryRequest{EntryId: "badid"})
	expectedError := status.Error(codes.NotFound, _notFoundErrMsg)
	expectedCallCounter.Done(&expectedError)
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
	expectedCallCounter = ds_telemetry.StartListRegistrationCall(s.expectedMetrics)
	entriesResp, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Require().Len(entriesResp.Entries, 2)

	// Make sure we deleted the right one
	expectedCallCounter = ds_telemetry.StartDeleteRegistrationCall(s.expectedMetrics)
	delRes, err := s.ds.DeleteRegistrationEntry(ctx, &datastore.DeleteRegistrationEntryRequest{EntryId: entry1.EntryId})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Require().Equal(entry1, delRes.Entry)

	// Make sure we have now only one registration entry
	expectedCallCounter = ds_telemetry.StartListRegistrationCall(s.expectedMetrics)
	entriesResp, err = s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Require().Len(entriesResp.Entries, 1)

	s.Require().Equal(s.expectedMetrics.AllMetrics(), s.m.AllMetrics())
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
				r, err := ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{Entry: entry})
				require.NoError(t, err)
				require.NotNil(t, r)
				require.NotNil(t, r.Entry)
				entry.EntryId = r.Entry.EntryId
			}
			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				ByParentId: &wrappers.StringValue{
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
				r, err := ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{Entry: entry})
				require.NoError(t, err)
				require.NotNil(t, r)
				require.NotNil(t, r.Entry)
				entry.EntryId = r.Entry.EntryId
			}
			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				BySelectors: &datastore.BySelectors{
					Selectors: test.selectors,
					Match:     datastore.BySelectors_MATCH_EXACT,
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
				r, err := ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{Entry: entry})
				require.NoError(t, err)
				require.NotNil(t, r)
				require.NotNil(t, r.Entry)
				entry.EntryId = r.Entry.EntryId
			}
			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				BySelectors: &datastore.BySelectors{
					Selectors: test.selectors,
					Match:     datastore.BySelectors_MATCH_SUBSET,
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
	_, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{
		Entry: makeFederatedRegistrationEntry(),
	})
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
	_, err := s.ds.DeleteBundle(context.Background(), &datastore.DeleteBundleRequest{
		TrustDomainId: "spiffe://otherdomain.org",
	})
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

	// delete the bundle in DELETE mode
	_, err := s.ds.DeleteBundle(context.Background(), &datastore.DeleteBundleRequest{
		TrustDomainId: "spiffe://otherdomain.org",
		Mode:          datastore.DeleteBundleRequest_DELETE,
	})
	s.Require().NoError(err)

	// verify that the registeration entry has been deleted
	resp, err := s.ds.FetchRegistrationEntry(context.Background(), &datastore.FetchRegistrationEntryRequest{
		EntryId: entry.EntryId,
	})
	s.Require().NoError(err)
	s.Require().Nil(resp.Entry)

	// make sure the unrelated entry still exists
	s.fetchRegistrationEntry(unrelated.EntryId)
}

func (s *PluginSuite) TestDeleteBundleDissociateRegistrationEntries() {
	// create the bundle and associated entry
	s.createBundle("spiffe://otherdomain.org")
	entry := s.createRegistrationEntry(makeFederatedRegistrationEntry())

	// delete the bundle in DISSOCIATE mode
	_, err := s.ds.DeleteBundle(context.Background(), &datastore.DeleteBundleRequest{
		TrustDomainId: "spiffe://otherdomain.org",
		Mode:          datastore.DeleteBundleRequest_DISSOCIATE,
	})
	s.Require().NoError(err)

	// make sure the entry still exists, albeit without an associated bundle
	entry = s.fetchRegistrationEntry(entry.EntryId)
	s.Require().Empty(entry.FederatesWith)
}

func (s *PluginSuite) TestCreateJoinToken() {
	now := time.Now().Unix()
	req := &datastore.CreateJoinTokenRequest{
		JoinToken: &datastore.JoinToken{
			Token:  "foobar",
			Expiry: now,
		},
	}
	expectedCallCounter := ds_telemetry.StartCreateJoinTokenCall(s.expectedMetrics)
	_, err := s.ds.CreateJoinToken(ctx, req)
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)

	// Make sure we can't re-register
	expectedCallCounter = ds_telemetry.StartCreateJoinTokenCall(s.expectedMetrics)
	_, err = s.ds.CreateJoinToken(ctx, req)
	expectedCallCounter.Done(&err)
	s.NotNil(err)

	s.Require().Equal(s.expectedMetrics.AllMetrics(), s.m.AllMetrics())
}

func (s *PluginSuite) TestCreateAndFetchJoinToken() {
	now := time.Now().Unix()
	joinToken := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: now,
	}

	expectedCallCounter := ds_telemetry.StartCreateJoinTokenCall(s.expectedMetrics)
	_, err := s.ds.CreateJoinToken(ctx, &datastore.CreateJoinTokenRequest{
		JoinToken: joinToken,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)

	expectedCallCounter = ds_telemetry.StartFetchJoinTokenCall(s.expectedMetrics)
	res, err := s.ds.FetchJoinToken(ctx, &datastore.FetchJoinTokenRequest{
		Token: joinToken.Token,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Equal("foobar", res.JoinToken.Token)
	s.Equal(now, res.JoinToken.Expiry)

	s.Require().Equal(s.expectedMetrics.AllMetrics(), s.m.AllMetrics())
}

func (s *PluginSuite) TestDeleteJoinToken() {
	now := time.Now().Unix()
	joinToken1 := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: now,
	}

	expectedCallCounter := ds_telemetry.StartCreateJoinTokenCall(s.expectedMetrics)
	_, err := s.ds.CreateJoinToken(ctx, &datastore.CreateJoinTokenRequest{
		JoinToken: joinToken1,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)

	joinToken2 := &datastore.JoinToken{
		Token:  "batbaz",
		Expiry: now,
	}

	expectedCallCounter = ds_telemetry.StartCreateJoinTokenCall(s.expectedMetrics)
	_, err = s.ds.CreateJoinToken(ctx, &datastore.CreateJoinTokenRequest{
		JoinToken: joinToken2,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)

	expectedCallCounter = ds_telemetry.StartDeleteJoinTokenCall(s.expectedMetrics)
	_, err = s.ds.DeleteJoinToken(ctx, &datastore.DeleteJoinTokenRequest{
		Token: joinToken1.Token,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)

	// Should not be able to fetch after delete
	expectedCallCounter = ds_telemetry.StartFetchJoinTokenCall(s.expectedMetrics)
	resp, err := s.ds.FetchJoinToken(ctx, &datastore.FetchJoinTokenRequest{
		Token: joinToken1.Token,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Nil(resp.JoinToken)

	// Second token should still be present
	expectedCallCounter = ds_telemetry.StartFetchJoinTokenCall(s.expectedMetrics)
	resp, err = s.ds.FetchJoinToken(ctx, &datastore.FetchJoinTokenRequest{
		Token: joinToken2.Token,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.AssertProtoEqual(joinToken2, resp.JoinToken)

	s.Require().Equal(s.expectedMetrics.AllMetrics(), s.m.AllMetrics())
}

func (s *PluginSuite) TestPruneJoinTokens() {
	now := time.Now().Unix()
	joinToken := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: now,
	}

	expectedCallCounter := ds_telemetry.StartCreateJoinTokenCall(s.expectedMetrics)
	_, err := s.ds.CreateJoinToken(ctx, &datastore.CreateJoinTokenRequest{
		JoinToken: joinToken,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)

	// Ensure we don't prune valid tokens, wind clock back 10s
	expectedCallCounter = ds_telemetry.StartPruneJoinTokenCall(s.expectedMetrics)
	_, err = s.ds.PruneJoinTokens(ctx, &datastore.PruneJoinTokensRequest{
		ExpiresBefore: now - 10,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)

	expectedCallCounter = ds_telemetry.StartFetchJoinTokenCall(s.expectedMetrics)
	resp, err := s.ds.FetchJoinToken(ctx, &datastore.FetchJoinTokenRequest{
		Token: joinToken.Token,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Equal("foobar", resp.JoinToken.Token)

	// Ensure we don't prune on the exact ExpiresBefore
	expectedCallCounter = ds_telemetry.StartPruneJoinTokenCall(s.expectedMetrics)
	_, err = s.ds.PruneJoinTokens(ctx, &datastore.PruneJoinTokensRequest{
		ExpiresBefore: now,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)

	expectedCallCounter = ds_telemetry.StartFetchJoinTokenCall(s.expectedMetrics)
	resp, err = s.ds.FetchJoinToken(ctx, &datastore.FetchJoinTokenRequest{
		Token: joinToken.Token,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Equal("foobar", resp.JoinToken.Token)

	// Ensure we prune old tokens
	joinToken.Expiry = (now + 10)
	expectedCallCounter = ds_telemetry.StartPruneJoinTokenCall(s.expectedMetrics)
	_, err = s.ds.PruneJoinTokens(ctx, &datastore.PruneJoinTokensRequest{
		ExpiresBefore: now + 10,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)

	expectedCallCounter = ds_telemetry.StartFetchJoinTokenCall(s.expectedMetrics)
	resp, err = s.ds.FetchJoinToken(ctx, &datastore.FetchJoinTokenRequest{
		Token: joinToken.Token,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Nil(resp.JoinToken)

	s.Require().Equal(s.expectedMetrics.AllMetrics(), s.m.AllMetrics())
}

func (s *PluginSuite) TestGetPluginInfo() {
	resp, err := s.ds.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
}

func (s *PluginSuite) TestDisabledMigrationBreakingChanges() {
	dbVersion := 8

	dbName := fmt.Sprintf("v%d.sqlite3", dbVersion)
	dbPath := filepath.Join(s.dir, "unsafe-disabled-migration-"+dbName)
	dump := migrationDump(dbVersion)
	s.Require().NotEmpty(dump, "no migration dump set up for version %d", dbVersion)
	s.Require().NoError(dumpDB(dbPath, dump), "error with DB dump for version %d", dbVersion)

	// configure the datastore to use the new database
	_, err := s.ds.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: fmt.Sprintf(`
				database_type = "sqlite3"
				connection_string = "file://%s"
				disable_migration = true
			`, dbPath),
	})
	s.Require().EqualError(err, "rpc error: code = Unknown desc = datastore-sql:"+
		" auto-migration must be enabled for current DB")
}

func (s *PluginSuite) TestMigration() {
	for i := 0; i < latestSchemaVersion; i++ {
		dbName := fmt.Sprintf("v%d.sqlite3", i)
		dbPath := filepath.Join(s.dir, "migration-"+dbName)
		dump := migrationDump(i)
		s.Require().NotEmpty(dump, "no migration dump set up for version %d", i)
		s.Require().NoError(dumpDB(dbPath, dump), "error with DB dump for version %d", i)

		// configure the datastore to use the new database
		_, err := s.ds.Configure(context.Background(), &spi.ConfigureRequest{
			Configuration: fmt.Sprintf(`
				database_type = "sqlite3"
				connection_string = "file://%s"
			`, dbPath),
		})
		s.Require().NoError(err)

		switch i {
		case 0:
			// the v0 database has two bundles. the spiffe://otherdomain.org
			// bundle has been soft-deleted. after migration, it should not
			// exist. if we try and create a bundle with the same id, it should
			// fail if the migration did not run, due to uniqueness
			// constraints.
			_, err := s.ds.CreateBundle(context.Background(), &datastore.CreateBundleRequest{
				Bundle: bundleutil.BundleProtoFromRootCAs("spiffe://otherdomain.org", nil),
			})
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
			db, _, _, err := sqliteDB{}.connect(&configuration{
				DatabaseType:     "sqlite3",
				ConnectionString: fmt.Sprintf("file://%s", dbPath),
			})
			s.Require().NoError(err)
			s.Require().True(db.Dialect().HasIndex("registered_entries", "idx_registered_entries_parent_id"))
			s.Require().True(db.Dialect().HasIndex("registered_entries", "idx_registered_entries_spiffe_id"))
			s.Require().True(db.Dialect().HasIndex("selectors", "idx_selectors_type_value"))
		case 9:
			db, _, _, err := sqliteDB{}.connect(&configuration{
				DatabaseType:     "sqlite3",
				ConnectionString: fmt.Sprintf("file://%s", dbPath),
			})
			s.Require().NoError(err)
			s.Require().True(db.Dialect().HasIndex("registered_entries", "idx_registered_entries_expiry"))
		case 10:
			db, _, _, err := sqliteDB{}.connect(&configuration{
				DatabaseType:     "sqlite3",
				ConnectionString: fmt.Sprintf("file://%s", dbPath),
			})
			s.Require().NoError(err)
			s.Require().True(db.Dialect().HasIndex("federated_registration_entries", "idx_federated_registration_entries_registered_entry_id"))
		case 11:
			db, _, _, err := sqliteDB{}.connect(&configuration{
				DatabaseType:     "sqlite3",
				ConnectionString: fmt.Sprintf("file://%s", dbPath),
			})
			s.Require().NoError(err)
			s.Require().True(db.Dialect().HasColumn("migrations", "code_version"))
		case 12:
			// Ensure attested_nodes_entries gained two new columns
			db, _, _, err := sqliteDB{}.connect(&configuration{
				DatabaseType:     "sqlite3",
				ConnectionString: fmt.Sprintf("file://%s", dbPath),
			})
			s.Require().NoError(err)
			// Assert migration version is now 13
			migration := Migration{}
			db.First(&migration)
			s.Require().Equal(13, migration.Version)

			// Assert attested_node_entries tables gained the new columns
			s.Require().True(db.Dialect().HasColumn("attested_node_entries", "new_serial_number"))
			s.Require().True(db.Dialect().HasColumn("attested_node_entries", "new_expires_at"))

			resp, err := s.ds.FetchAttestedNode(context.Background(), &datastore.FetchAttestedNodeRequest{
				SpiffeId: "spiffe://example.org/host",
			})
			s.Require().NoError(err)

			// Assert current serial numbers and expiration time remains the same
			expectedTime, err := time.Parse(time.RFC3339, "2018-12-19T15:26:58-07:00")
			s.Require().NoError(err)
			s.Require().Equal(expectedTime.Unix(), resp.Node.CertNotAfter)
			s.Require().Equal("111", resp.Node.CertSerialNumber)

			// Assert the new fields are empty for pre-existing entries
			s.Require().Empty(resp.Node.NewCertSerialNumber)
			s.Require().Empty(resp.Node.NewCertNotAfter)
		default:
			s.T().Fatalf("no migration test added for version %d", i)
		}
	}
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

		_, err := s.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{Node: node})
		require.NoError(t, err)
		_, err = s.ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{SpiffeId: node.SpiffeId})
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
	expectedCallCounter := ds_telemetry.StartFetchBundleCall(s.expectedMetrics)
	resp, err := s.ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: trustDomainID,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	return resp.Bundle
}

func (s *PluginSuite) createBundle(trustDomainID string) {
	expectedCallCounter := ds_telemetry.StartFetchBundleCall(s.expectedMetrics)
	_, err := s.ds.CreateBundle(ctx, &datastore.CreateBundleRequest{
		Bundle: bundleutil.BundleProtoFromRootCA(trustDomainID, s.cert),
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
}

func (s *PluginSuite) createRegistrationEntry(entry *common.RegistrationEntry) *common.RegistrationEntry {
	expectedCallCounter := ds_telemetry.StartCreateRegistrationCall(s.expectedMetrics)
	resp, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{
		Entry: entry,
	})
	expectedCallCounter.Done(nil)
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().NotNil(resp.Entry)
	return resp.Entry
}

func (s *PluginSuite) fetchRegistrationEntry(entryID string) *common.RegistrationEntry {
	resp, err := s.ds.FetchRegistrationEntry(ctx, &datastore.FetchRegistrationEntryRequest{
		EntryId: entryID,
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().NotNil(resp.Entry)
	return resp.Entry
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
	callCounter := ds_telemetry.StartGetNodeSelectorsCall(s.expectedMetrics)
	defer callCounter.Done(nil)
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

func (s *PluginSuite) setNodeSelectors(spiffeID string, selectors []*common.Selector) {
	callCounter := ds_telemetry.StartSetNodeSelectorsCall(s.expectedMetrics)
	resp, err := s.ds.SetNodeSelectors(ctx, &datastore.SetNodeSelectorsRequest{
		Selectors: &datastore.NodeSelectors{
			SpiffeId:  spiffeID,
			Selectors: selectors,
		},
	})
	callCounter.Done(nil)
	s.Require().NoError(err)
	s.RequireProtoEqual(&datastore.SetNodeSelectorsResponse{}, resp)
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
			conn_max_lifetime = "1ms"
			`,
			expectMaxOpenConns: 1000,
			expectIdle:         50,
		},
	}

	for _, tt := range tests {
		tt := tt
		s.T().Run(tt.desc, func(t *testing.T) {
			p := New()

			metricsService := metricsservice.New(metricsservice.Config{
				Metrics: s.m,
			})
			var ds datastore.Plugin
			pluginDone := spiretest.LoadPlugin(t, builtin(p), &ds,
				spiretest.HostService(proto_services.MetricsServiceHostServiceServer(metricsService)))
			defer pluginDone()

			dbPath := filepath.Join(s.dir, "test-datastore-configure.sqlite3")

			_, err := ds.Configure(context.Background(), &spi.ConfigureRequest{
				Configuration: fmt.Sprintf(`
				database_type = "sqlite3"
				log_sql = true
				connection_string = "%s"
				%s
			`, dbPath, tt.giveDBConfig),
			})
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
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
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
	SELECT id FROM registered_entries WHERE parent_id = ?
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"spiffe-id"},
			query: `
WITH listing AS (
	SELECT id FROM registered_entries WHERE spiffe_id = ?
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "spiffe-id"},
			query: `
WITH listing AS (
	SELECT id FROM registered_entries WHERE parent_id = ? AND spiffe_id = ?
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"selector-subset-one"},
			query: `
WITH listing AS (
	SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"selector-subset-many"},
			query: `
WITH listing AS (
	SELECT id FROM (
		SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
		UNION
		SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
	) s_0
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"selector-exact-one"},
			query: `
WITH listing AS (
	SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"selector-exact-many"},
			query: `
WITH listing AS (
	SELECT id FROM (
		SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
		INTERSECT
		SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
	) s_0
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "selector-subset-one"},
			query: `
WITH listing AS (
	SELECT id FROM (
		SELECT id FROM registered_entries WHERE parent_id = ?
		INTERSECT
		SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
	) s_0
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "selector-subset-many"},
			query: `
WITH listing AS (
	SELECT id FROM (
		SELECT id FROM registered_entries WHERE parent_id = ?
		INTERSECT
		SELECT id FROM (
			SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
			UNION
			SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
		) s_1
	) s_0
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "selector-exact-one"},
			query: `
WITH listing AS (
	SELECT id FROM (
		SELECT id FROM registered_entries WHERE parent_id = ?
		INTERSECT
		SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
	) s_0
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "selector-exact-many"},
			query: `
WITH listing AS (
	SELECT id FROM (
		SELECT id FROM registered_entries WHERE parent_id = ?
		INTERSECT
		SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
		INTERSECT
		SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
	) s_0
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			paged:   "no-token",
			query: `
WITH listing AS (
	SELECT id FROM registered_entries ORDER BY id ASC LIMIT 1
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT id FROM registered_entries WHERE id > ? ORDER BY id ASC LIMIT 1
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"spiffe-id"},
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT id FROM registered_entries WHERE spiffe_id = ? AND id > ? ORDER BY id ASC LIMIT 1
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"spiffe-id", "selector-exact-one"},
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT id FROM (
		SELECT id FROM registered_entries WHERE spiffe_id = ?
		INTERSECT
		SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
	) s_0 WHERE id > ? ORDER BY id ASC LIMIT 1
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			query: `
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
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
	SELECT id FROM registered_entries WHERE parent_id = $1
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"spiffe-id"},
			query: `
WITH listing AS (
	SELECT id FROM registered_entries WHERE spiffe_id = $1
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "spiffe-id"},
			query: `
WITH listing AS (
	SELECT id FROM registered_entries WHERE parent_id = $1 AND spiffe_id = $2
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"selector-subset-one"},
			query: `
WITH listing AS (
	SELECT registered_entry_id AS id FROM selectors WHERE type = $1 AND value = $2
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"selector-subset-many"},
			query: `
WITH listing AS (
	SELECT id FROM (
		SELECT registered_entry_id AS id FROM selectors WHERE type = $1 AND value = $2
		UNION
		SELECT registered_entry_id AS id FROM selectors WHERE type = $3 AND value = $4
	) s_0
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"selector-exact-one"},
			query: `
WITH listing AS (
	SELECT registered_entry_id AS id FROM selectors WHERE type = $1 AND value = $2
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"selector-exact-many"},
			query: `
WITH listing AS (
	SELECT id FROM (
		SELECT registered_entry_id AS id FROM selectors WHERE type = $1 AND value = $2
		INTERSECT
		SELECT registered_entry_id AS id FROM selectors WHERE type = $3 AND value = $4
	) s_0
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "selector-subset-one"},
			query: `
WITH listing AS (
	SELECT id FROM (
		SELECT id FROM registered_entries WHERE parent_id = $1
		INTERSECT
		SELECT registered_entry_id AS id FROM selectors WHERE type = $2 AND value = $3
	) s_0
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "selector-subset-many"},
			query: `
WITH listing AS (
	SELECT id FROM (
		SELECT id FROM registered_entries WHERE parent_id = $1
		INTERSECT
		SELECT id FROM (
			SELECT registered_entry_id AS id FROM selectors WHERE type = $2 AND value = $3
			UNION
			SELECT registered_entry_id AS id FROM selectors WHERE type = $4 AND value = $5
		) s_1
	) s_0
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "selector-exact-one"},
			query: `
WITH listing AS (
	SELECT id FROM (
		SELECT id FROM registered_entries WHERE parent_id = $1
		INTERSECT
		SELECT registered_entry_id AS id FROM selectors WHERE type = $2 AND value = $3
	) s_0
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "selector-exact-many"},
			query: `
WITH listing AS (
	SELECT id FROM (
		SELECT id FROM registered_entries WHERE parent_id = $1
		INTERSECT
		SELECT registered_entry_id AS id FROM selectors WHERE type = $2 AND value = $3
		INTERSECT
		SELECT registered_entry_id AS id FROM selectors WHERE type = $4 AND value = $5
	) s_0
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			paged:   "no-token",
			query: `
WITH listing AS (
	SELECT id FROM registered_entries ORDER BY id ASC LIMIT 1
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT id FROM registered_entries WHERE id > $1 ORDER BY id ASC LIMIT 1
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"spiffe-id"},
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT id FROM registered_entries WHERE spiffe_id = $1 AND id > $2 ORDER BY id ASC LIMIT 1
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"spiffe-id", "selector-exact-one"},
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT id FROM (
		SELECT id FROM registered_entries WHERE spiffe_id = $1
		INTERSECT
		SELECT registered_entry_id AS id FROM selectors WHERE type = $2 AND value = $3
	) s_0 WHERE id > $4 ORDER BY id ASC LIMIT 1
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

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
	D.value AS dns_name
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
	D.value AS dns_name
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
	SELECT id FROM registered_entries WHERE parent_id = ?
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
	D.value AS dns_name
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
	SELECT id FROM registered_entries WHERE spiffe_id = ?
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
	D.value AS dns_name
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
	SELECT id FROM registered_entries WHERE parent_id = ? AND spiffe_id = ?
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
	D.value AS dns_name
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
	SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
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
	D.value AS dns_name
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
	SELECT id FROM (
		SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
		UNION
		SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
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
	D.value AS dns_name
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
	SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
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
	D.value AS dns_name
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
	SELECT DISTINCT id FROM (
		(SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(id)
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
	D.value AS dns_name
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
	SELECT DISTINCT id FROM (
		(SELECT id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(id)
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
	D.value AS dns_name
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
	SELECT DISTINCT id FROM (
		(SELECT id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT id FROM (
			SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
			UNION
			SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
		) s_1) c_1
		USING(id)
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
	D.value AS dns_name
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
	SELECT DISTINCT id FROM (
		(SELECT id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(id)
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
	D.value AS dns_name
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
	SELECT DISTINCT id FROM (
		(SELECT id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(id)
		INNER JOIN
		(SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?) c_2
		USING(id)
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
	D.value AS dns_name
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
	SELECT id FROM (
		SELECT id FROM registered_entries ORDER BY id ASC LIMIT 1
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
	D.value AS dns_name
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
	SELECT id FROM (
		SELECT id FROM registered_entries WHERE id > ? ORDER BY id ASC LIMIT 1
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
	D.value AS dns_name
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
	SELECT id FROM (
		SELECT id FROM registered_entries WHERE spiffe_id = ? AND id > ? ORDER BY id ASC LIMIT 1
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
	D.value AS dns_name
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
	SELECT id FROM (
		SELECT DISTINCT id FROM (
			(SELECT id FROM registered_entries WHERE spiffe_id = ?) c_0
			INNER JOIN
			(SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?) c_1
			USING(id)
		) WHERE id > ? ORDER BY id ASC LIMIT 1
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
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
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
	SELECT id FROM registered_entries WHERE parent_id = ?
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"spiffe-id"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT id FROM registered_entries WHERE spiffe_id = ?
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "spiffe-id"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT id FROM registered_entries WHERE parent_id = ? AND spiffe_id = ?
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"selector-subset-one"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"selector-subset-many"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT id FROM (
		SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
		UNION
		SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
	) s_0
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"selector-exact-one"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"selector-exact-many"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT id FROM (
		(SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(id)
	)
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "selector-subset-one"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT id FROM (
		(SELECT id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(id)
	)
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "selector-subset-many"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT id FROM (
		(SELECT id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT id FROM (
			SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
			UNION
			SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?
		) s_1) c_1
		USING(id)
	)
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "selector-exact-one"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT id FROM (
		(SELECT id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(id)
	)
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "selector-exact-many"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT id FROM (
		(SELECT id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(id)
		INNER JOIN
		(SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?) c_2
		USING(id)
	)
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			paged:       "no-token",
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT id FROM (
		SELECT id FROM registered_entries ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			paged:       "with-token",
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT id FROM (
		SELECT id FROM registered_entries WHERE id > ? ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

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
	SELECT id FROM (
		SELECT id FROM registered_entries WHERE spiffe_id = ? AND id > ? ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

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
	SELECT id FROM (
		SELECT DISTINCT id FROM (
			(SELECT id FROM registered_entries WHERE spiffe_id = ?) c_0
			INNER JOIN
			(SELECT registered_entry_id AS id FROM selectors WHERE type = ? AND value = ?) c_1
			USING(id)
		) WHERE id > ? ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
SELECT
	id as e_id,
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
	NULL AS dns_name
FROM
	registered_entries
WHERE id IN (SELECT id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value
FROM
	dns_names
WHERE registered_entry_id IN (SELECT id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT id FROM listing)

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
					req.ByParentId = &wrappers.StringValue{
						Value: "spiffe://parent",
					}
				case "spiffe-id":
					req.BySpiffeId = &wrappers.StringValue{
						Value: "spiffe://id",
					}
				case "selector-subset-one":
					req.BySelectors = &datastore.BySelectors{
						Selectors: []*common.Selector{{Type: "a", Value: "1"}},
						Match:     datastore.BySelectors_MATCH_SUBSET,
					}
				case "selector-subset-many":
					req.BySelectors = &datastore.BySelectors{
						Selectors: []*common.Selector{{Type: "a", Value: "1"}, {Type: "b", Value: "2"}},
						Match:     datastore.BySelectors_MATCH_SUBSET,
					}
				case "selector-exact-one":
					req.BySelectors = &datastore.BySelectors{
						Selectors: []*common.Selector{{Type: "a", Value: "1"}},
						Match:     datastore.BySelectors_MATCH_EXACT,
					}
				case "selector-exact-many":
					req.BySelectors = &datastore.BySelectors{
						Selectors: []*common.Selector{{Type: "a", Value: "1"}, {Type: "b", Value: "2"}},
						Match:     datastore.BySelectors_MATCH_EXACT,
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

	dropTablesInRows(t, db, rows)
}

func wipeMySQL(t *testing.T, connString string) {
	db, err := sql.Open("mysql", connString)
	require.NoError(t, err)
	defer db.Close()

	rows, err := db.Query(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'spire';`)
	require.NoError(t, err)
	defer rows.Close()

	dropTablesInRows(t, db, rows)
}

func dropTablesInRows(t *testing.T, db *sql.DB, rows *sql.Rows) {
	for rows.Next() {
		var q string
		err := rows.Scan(&q)
		require.NoError(t, err)
		_, err = db.Exec("DROP TABLE IF EXISTS " + q + " CASCADE")
		require.NoError(t, err)
	}
	require.NoError(t, rows.Err())
}
