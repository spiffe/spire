package datastore_test

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/protoutil"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/datastore/sqlstore"
	"github.com/spiffe/spire/pkg/server/datastore/testdata"
	ds_plugin "github.com/spiffe/spire/pkg/server/plugin/datastore"
	cassandra_plugin "github.com/spiffe/spire/pkg/server/plugin/datastore/cassandra"
	"github.com/spiffe/spire/proto/private/server/journal"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/plugintest"
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
)

const (
	_ttl                                   = time.Hour
	_expiredNotAfterString                 = "2018-01-10T01:34:00+00:00"
	_validNotAfterString                   = "2018-01-10T01:36:00+00:00"
	_middleTimeString                      = "2018-01-10T01:35:00+00:00"
	datastoreSQLNotFoundErrorMessage       = "datastore-sql: record not found"
	datastoreCassandraNotFoundErrorMessage = "datastore(cassandra): record not found"
)

var _notFoundErrMsg = func() string {
	if TestDialect == "cassandra" {
		return datastoreCassandraNotFoundErrorMessage
	}

	return datastoreSQLNotFoundErrorMessage
}()

func wrapErrMsg(msg string) string {
	// The plugin framework will enrich errors returned by plugins with additional
	// context, so we need to be able to wrap the error when using a plugin-based
	// datastore.
	if TestDialect == "cassandra" && !strings.HasPrefix(msg, "datastore(cassandra):") && len(msg) > 0 {
		return fmt.Sprintf("datastore(cassandra): %s", msg)
	}
	return msg
}

func TestPlugin(t *testing.T) {
	spiretest.Run(t, new(PluginSuite))
}

type PluginSuite struct {
	spiretest.Suite

	cert   *x509.Certificate
	cacert *x509.Certificate

	dir            string
	nextID         int
	ds             datastore.DataStore
	configurableDs datastore.ConfigurableDataStore
	hook           *test.Hook
	dsCloser       func() error
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
}

func (s *PluginSuite) SetupTest() {
	s.dir = s.TempDir()
	s.ds = s.newPlugin()
}

func (s *PluginSuite) TearDownTest() {
	if s.ds != nil {
		s.ds.Close()
	}
	// if s.dsCloser != nil {
	// 	s.dsCloser()
	// }
}

func (s *PluginSuite) loadCassandraAsBuiltin(t *testing.T, log *logrus.Logger) datastore.DataStore {
	v1 := new(ds_plugin.V1Alpha1)

	parts := strings.Split(TestConnString, ";")
	s.Require().Len(parts, 2, "addresses and keyspace must both be provided for cassandra tests")
	keyspace := parts[1]
	var addresses []string
	err := json.Unmarshal([]byte(parts[0]), &addresses)
	s.Require().NoError(err, "addresses should be a valid json string containing an array of strings")

	datastoreConfig := fmt.Sprintf(`
		hosts = ["%s"]
		keyspace = "%s"
		num_conns = 10
		connect_timeout_ms = "10000"
		read_timeout_ms = "10000"
		write_timeout_ms = "11000"
		driver_log_level = "ERROR"
		write_consistency = "QUORUM"
		read_consistency = "QUORUM"
		`, strings.Join(addresses, `", "`), keyspace)

	p := plugintest.Load(s.T(), cassandra_plugin.BuiltIn(), v1,
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		// This should be sufficent for tests but we may want to change it in the future
		plugintest.MaxGrpcMessageSize(1_000_000_000),
		plugintest.Configure(datastoreConfig),
		// plugintest.Log(log), // TODO(tjons): this doesn't actually work
	)

	wipeCassandra(t, addresses, keyspace) // This is fine here as long as we are using the DROP KEYSPACE approach
	s.dsCloser = func() error {
		err := p.Close()
		if err != nil {
			log.Errorf("Error closing datastore plugin: %s", err.Error())
		}

		return nil
	}

	return v1
}

func (s *PluginSuite) newPlugin() datastore.DataStore {
	log, hook := test.NewNullLogger()
	var ds datastore.DataStore
	s.hook = hook

	// When the test suite is executed normally, we test against sqlite3 since
	// it requires no external dependencies. The integration test framework
	// builds the test harness for a specific dialect and connection string
	switch TestDialect {
	case "":
		sqlLiteStore := sqlstore.New(log)
		s.nextID++
		dbPath := filepath.ToSlash(filepath.Join(s.dir, fmt.Sprintf("db%d.sqlite3", s.nextID)))
		_, err := sqlLiteStore.Configure(ctx, &configv1.ConfigureRequest{
			HclConfiguration: fmt.Sprintf(`
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
		rawDb := sqlLiteStore.GetUnderlyingDBForTesting()
		rawDb.Raw("PRAGMA journal_mode").Scan(&jm)
		s.Require().Equal(jm.JournalMode, "wal")

		// assert that foreign_key support is enabled
		fk := struct {
			ForeignKeys string
		}{}
		rawDb.Raw("PRAGMA foreign_keys").Scan(&fk)
		s.Require().Equal(fk.ForeignKeys, "1")

		s.configurableDs = sqlLiteStore
		ds = sqlLiteStore
	case "mysql":
		mysqlStore := sqlstore.New(log)

		s.T().Logf("CONN STRING: %q", TestConnString)
		s.Require().NotEmpty(TestConnString, "connection string must be set")
		wipeMySQL(s.T(), TestConnString)

		_, err := mysqlStore.Configure(ctx, &configv1.ConfigureRequest{
			HclConfiguration: fmt.Sprintf(`
			database_type = "mysql"
			log_sql = true
			connection_string = "%s"
			ro_connection_string = "%s"
		`, TestConnString, TestROConnString),
		})
		s.Require().NoError(err)

		s.configurableDs = mysqlStore
		ds = mysqlStore
	case "postgres":
		postgresStore := sqlstore.New(log)

		s.T().Logf("CONN STRING: %q", TestConnString)
		s.Require().NotEmpty(TestConnString, "connection string must be set")
		wipePostgres(s.T(), TestConnString)
		_, err := postgresStore.Configure(ctx, &configv1.ConfigureRequest{
			HclConfiguration: fmt.Sprintf(`	
			database_type = "postgres"
			log_sql = true
			connection_string = "%s"
			ro_connection_string = "%s"
		`, TestConnString, TestROConnString)})
		s.Require().NoError(err)

		s.configurableDs = postgresStore
		ds = postgresStore
	case "cassandra":
		s.T().Logf("CONN STRING: %q", TestConnString)
		ds = s.loadCassandraAsBuiltin(s.T(), log)
	default:
		s.Require().FailNowf("Unsupported external test dialect %q", TestDialect)
	}

	return ds
}

func wipeCassandra(t *testing.T, addresses []string, keyspace string) {
	cluster := gocql.NewCluster(addresses...)
	cluster.NumConns = 2
	cluster.ConnectTimeout = 10 * time.Second
	cluster.WriteTimeout = 11 * time.Second
	cluster.Timeout = 10 * time.Second
	cluster.Consistency = gocql.All
	var errCount int

sess:
	sess, err := cluster.CreateSession()
	if err != nil {
		errCount++
		if errCount > 5 {
			t.Fatalf("could not create cassandra session for wiping: %v", err)
		}
		time.Sleep(2 * time.Second)
		goto sess
	}

	// This approach of dropping the keyspace is easier than cleaning up the tables
	// iteratively, but due to resource issues with connection pooling in the test suite,
	// it's safer to truncate the tables one by one for now.
	/*
		dropKeyspaceCQL := fmt.Sprintf("DROP KEYSPACE IF EXISTS %s", keyspace)
		if err := sess.Query(dropKeyspaceCQL).Exec(); err != nil {
			if !strings.Contains(err.Error(), "does not exist") {
				t.Fatalf("could not drop cassandra keyspace %q: %v", keyspace, err)
			}
		}
	*/

	tables := []string{
		"registered_entries",
		"registration_entry_events",
		"attested_node_entries",
		"attested_node_entries_events",
		"bundles",
		"ca_journals",
		"federated_trust_domains",
		"join_tokens",
	}

	for _, table := range tables {
		for attempt := 1; attempt <= 5; attempt++ {
			truncateCQL := fmt.Sprintf("TRUNCATE %s.%s", keyspace, table)
			if err := sess.Query(truncateCQL).Consistency(gocql.All).Exec(); err != nil {
				t.Fatalf("could not truncate cassandra table %q: %v", table, err)
			}

			var count int
			countCQL := fmt.Sprintf("SELECT COUNT(*) FROM %s.%s", keyspace, table)
			if err := sess.Query(countCQL).Consistency(gocql.All).Scan(&count); err != nil {
				t.Logf("attempt %d: could not verify truncation of table %q: %v", attempt, table, err)
				continue
			}
			if count != 0 {
				t.Logf("attempt %d: table %q is not empty after truncation, count is %d", attempt, table, count)
				time.Sleep(1 * time.Second)
				continue
			}

			break
		}
	}

	sess.Close()
}

func (s *PluginSuite) TestInvalidPluginConfiguration() {
	if s.configurableDs == nil {
		s.T().Skip("plugin configuration tests only apply to configurable plugins")
	}

	_, err := s.configurableDs.Configure(ctx, &configv1.ConfigureRequest{
		HclConfiguration: `
		database_type = "wrong"
		connection_string = "bad"
		`,
	})
	s.RequireErrorContains(err, "datastore-sql: unsupported database_type: wrong")
}

func (s *PluginSuite) TestInvalidAWSConfiguration() {
	if s.configurableDs == nil {
		s.T().Skip("plugin configuration tests only apply to configurable plugins")
	}

	testCases := []struct {
		name        string
		config      string
		expectedErr string
	}{
		{
			name: "aws_mysql - no region",
			config: `
			database_type "aws_mysql" {}
			connection_string = "test_user:@tcp(localhost:1234)/spire?parseTime=true&allowCleartextPasswords=1&tls=true"`,
			expectedErr: "datastore-sql: region must be specified",
		},
		{
			name: "postgres_mysql - no region",
			config: `
			database_type "aws_postgres" {}
			connection_string = "dbname=postgres user=postgres host=the-host sslmode=require"`,
			expectedErr: "region must be specified",
		},
	}
	for _, testCase := range testCases {
		s.T().Run(testCase.name, func(t *testing.T) {
			_, err := s.configurableDs.Configure(ctx, &configv1.ConfigureRequest{
				HclConfiguration: testCase.config,
			})
			s.RequireErrorContains(err, testCase.expectedErr)
		})
	}
}

func (s *PluginSuite) TestInvalidMySQLConfiguration() {
	if s.configurableDs == nil {
		s.T().Skip("plugin configuration tests only apply to configurable plugins")
	}

	_, err := s.configurableDs.Configure(ctx, &configv1.ConfigureRequest{
		HclConfiguration: `
		database_type = "mysql"
		connection_string = "username:@tcp(127.0.0.1)/spire_test"
		`,
	})
	s.RequireErrorContains(err, "datastore-sql: invalid mysql config: missing parseTime=true param in connection_string")

	_, err = s.configurableDs.Configure(ctx, &configv1.ConfigureRequest{
		HclConfiguration: `
		database_type = "mysql"
		ro_connection_string = "username:@tcp(127.0.0.1)/spire_test"
		`,
	})
	s.RequireErrorContains(err, "datastore-sql: connection_string must be set")

	_, err = s.configurableDs.Configure(ctx, &configv1.ConfigureRequest{
		HclConfiguration: `
		database_type = "mysql"
		`,
	})
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
	//
	// in this test suite, it's important that we write the returned bundle back to the variable,
	// since the object can be passed over gRPC to a plugin where we will not see changes to
	// it on the plugin side. The sqlstore plugin leverages the fact that the original object is mutated
	// by the datastore, which is an antipattern.
	bundle, err = s.ds.CreateBundle(ctx, bundle)
	s.Require().NoError(err)

	// create again (constraint violation)
	_, err = s.ds.CreateBundle(ctx, bundle)
	s.Require().Equal(status.Code(err), codes.AlreadyExists)

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
	bundle.SequenceNumber++ // we will now expected the sequence number to be 1 from the AppendBundle call

	// append identical
	ab, err = s.ds.AppendBundle(ctx, bundle2)
	s.Require().NoError(err)
	s.Require().NotNil(ab)
	s.AssertProtoEqual(appendedBundle, ab)

	// append on a new bundle
	bundle3 := bundleutil.BundleProtoFromRootCA("spiffe://bar", s.cacert)
	appendedBundle3, err := s.ds.AppendBundle(ctx, bundle3)
	s.Require().NoError(err)
	s.AssertProtoEqual(bundle3, appendedBundle3)

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

// paginationTest describes a test for iterating through the pages of
// a database call that supports pagination.
type paginationTest[T any] struct {
	name             string
	totalItems       int
	pageSize         int32
	currentPage      int
	token            string
	allExpectedItems []T
	receivedItems    []T
	getResponse      pageLister[T]
	identify         func(T) string
	expectOrder      bool
	assertionFunc    func(t *testing.T, expected, actual T)
}

type pageLister[T any] func(pagination *datastore.Pagination) ([]T, *datastore.Pagination, error)

func NewPaginationTest[T any](named string) *paginationTest[T] {
	return &paginationTest[T]{name: named}
}

func (p *paginationTest[T]) WithExpectedItems(items []T) *paginationTest[T] {
	p.totalItems = len(items)
	p.allExpectedItems = items
	p.receivedItems = make([]T, 0, len(p.allExpectedItems))
	return p
}

func (p *paginationTest[T]) WithPageSize(c int32) *paginationTest[T] {
	p.pageSize = c

	return p
}

func (p *paginationTest[T]) WithExpectOrder(expectOrder bool) *paginationTest[T] {
	p.expectOrder = expectOrder

	return p
}

func (p *paginationTest[T]) WithLister(lister pageLister[T]) *paginationTest[T] {
	p.getResponse = lister
	return p
}

func (p *paginationTest[T]) WithAssertionFunc(assertionFunc func(t *testing.T, expected, actual T)) *paginationTest[T] {
	p.assertionFunc = assertionFunc
	return p
}

func (p *paginationTest[T]) NextPage() bool {
	if p.pageSize <= 0 {
		return false
	}

	if len(p.receivedItems) >= len(p.allExpectedItems) {
		return false
	}

	return true
}

func (p *paginationTest[T]) Pagination() *datastore.Pagination {
	if p.pageSize <= 0 {
		return nil
	}

	return &datastore.Pagination{
		PageSize: p.pageSize,
		Token:    p.token,
	}
}

func (p *paginationTest[T]) Get() error {
	pageItems, nextPage, err := p.getResponse(p.Pagination())
	if err != nil {
		return err
	}

	for _, pi := range pageItems {
		p.receivedItems = append(p.receivedItems, pi)
	}

	if nextPage != nil {
		p.token = nextPage.Token
	}

	p.currentPage++

	return nil
}

func (p *paginationTest[T]) Assert(t *testing.T) {
	t.Run(fmt.Sprintf("%s: interating through all pages", p.name), func(t *testing.T) {
		require.Lenf(t, p.receivedItems, p.totalItems, "received items length does not match expected")

		pageCount := (len(p.allExpectedItems) / int(p.pageSize)) + len(p.allExpectedItems)%int(p.pageSize)
		require.Equal(t, p.currentPage, pageCount, "number of pages iterated does not match expected")

		p.checkList(t)
	})
}

func (p *paginationTest[T]) reset() {
	p.currentPage = 0
	p.token = ""
	p.receivedItems = make([]T, 0, len(p.allExpectedItems))
}

func (p *paginationTest[T]) AssertNoPagination(t *testing.T) {
	t.Run(fmt.Sprintf("%s: getting all items without pagination", p.name), func(t *testing.T) {
		p.pageSize = 0
		p.reset()

		err := p.Get()
		require.NoError(t, err, "getting items without pagination should not error")

		p.checkList(t)
	})
}

func (p *paginationTest[T]) AssertBigPage(t *testing.T) {
	t.Run(fmt.Sprintf("%s: getting all items with a page size larger than total items", p.name), func(t *testing.T) {
		p.pageSize = int32(len(p.allExpectedItems) + 10)
		p.reset()

		err := p.Get()
		require.NoError(t, err, "getting items with a page size larger than total items should not error")

		p.checkList(t)

		require.Equal(
			t, 1, p.currentPage, "only one page should be returned when page size is larger than total items",
		)

		require.Equal(
			t, "", p.token, "pagination token should be empty when page size is larger than total items",
		)
	})
}

func (p *paginationTest[T]) WithIdentifier(f func(T) string) *paginationTest[T] {
	p.identify = f

	return p
}

func (p *paginationTest[T]) checkList(t *testing.T) {
	if p.assertionFunc != nil {
		require.Len(t, p.receivedItems, len(p.allExpectedItems), "assertion function provided but received items length does not match expected")

		if p.expectOrder {
			for i := range p.allExpectedItems {
				p.assertionFunc(t, p.allExpectedItems[i], p.receivedItems[i])
			}
		} else {
			expMap := make(map[string]T, len(p.allExpectedItems))
			gotMap := make(map[string]T, len(p.receivedItems))
			for _, cmp := range p.allExpectedItems {
				expMap[p.identify(cmp)] = cmp
			}

			for _, item := range p.receivedItems {
				gotMap[p.identify(item)] = item
			}

			for id, exp := range expMap {
				got, ok := gotMap[id]
				require.True(t, ok, "expected item not found in received items")
				p.assertionFunc(t, exp, got)
			}
		}

		return // we will return here when using the assertion func, since the assertion func is responsible for asserting the equality of the items
	}

	_, isProto := any(*new(T)).(proto.Message)
	if isProto {
		if p.expectOrder {
			spiretest.RequireProtoListEqual(
				t, p.allExpectedItems, p.receivedItems)
		} else {
			spiretest.RequireProtoListsSameEls(
				t, p.allExpectedItems, p.receivedItems,
			)
		}
	} else {
		if p.expectOrder {
			require.Equal(t, p.allExpectedItems, p.receivedItems)
		} else {
			require.ElementsMatch(t, p.allExpectedItems, p.receivedItems)
		}
	}
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
		expectedCode       codes.Code
		expectedErr        string
	}{
		{
			name: "pagination page size is zero",
			pagination: &datastore.Pagination{
				PageSize: 0,
			},
			expectedErr:  wrapErrMsg("cannot paginate with pagesize = 0"),
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "invalid token",
			expectedList: []*common.Bundle{},
			expectedErr:  wrapErrMsg("could not parse token 'invalid token'"),
			expectedCode: codes.InvalidArgument,
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
		s.T().Run(test.name, func(t *testing.T) {
			resp, err := s.ds.ListBundles(ctx, &datastore.ListBundlesRequest{
				Pagination: test.pagination,
			})
			if test.expectedErr != "" {
				s.AssertGRPCStatus(err, test.expectedCode, test.expectedErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)

			spiretest.RequireProtoListEqual(t, test.expectedList, resp.Bundles)
			require.Equal(t, test.expectedPagination, resp.Pagination)
		})
	}
	s.T().Run("standard paging endpoint test", func(t *testing.T) {
		listTest := NewPaginationTest[*common.Bundle]("ListBundlesWithPagination").
			WithExpectOrder(false).
			WithExpectedItems([]*common.Bundle{bundle1, bundle2, bundle3, bundle4}).
			WithPageSize(2).
			WithLister(func(p *datastore.Pagination) ([]*common.Bundle, *datastore.Pagination, error) {
				resp, err := s.ds.ListBundles(ctx, &datastore.ListBundlesRequest{
					Pagination: p,
				})
				if err != nil {
					return nil, nil, err
				}

				return resp.Bundles, resp.Pagination, nil
			})

		for listTest.NextPage() {
			s.Require().NoError(listTest.Get())
		}

		// common should also get without pagination
		// common should also get with a page size larger than the total items
		// common should error with invalid pagination
		listTest.Assert(s.T())
		listTest.AssertNoPagination(s.T())
		listTest.AssertBigPage(s.T())
	})
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
	count, err := s.ds.CountAttestedNodes(ctx, &datastore.CountAttestedNodesRequest{})
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
	count, err = s.ds.CountAttestedNodes(ctx, &datastore.CountAttestedNodesRequest{})
	s.Require().NoError(err)
	s.Require().Equal(int32(2), count)
}

func (s *PluginSuite) TestCountRegistrationEntries() {
	// Count empty registration entries
	count, err := s.ds.CountRegistrationEntries(ctx, &datastore.CountRegistrationEntriesRequest{})
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
	count, err = s.ds.CountRegistrationEntries(ctx, &datastore.CountRegistrationEntriesRequest{})
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
	s.AssertGRPCStatus(err, codes.Unknown, wrapErrMsg("prune failed: would prune all certificates"))
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

	// Tainted public key on raw format
	skID := x509util.SubjectKeyIDToString(s.cert.SubjectKeyId)

	t.Run("bundle not found", func(t *testing.T) {
		err := s.ds.TaintX509CA(ctx, "spiffe://foo", "foo")
		spiretest.RequireGRPCStatus(t, err, codes.NotFound, _notFoundErrMsg)
	})

	// Create Malformed CA
	bundle := bundleutil.BundleProtoFromRootCAs("spiffe://foo", []*x509.Certificate{{Raw: []byte("bar")}})
	_, err := s.ds.CreateBundle(ctx, bundle)
	require.NoError(t, err)

	t.Run("bundle not found", func(t *testing.T) {
		err := s.ds.TaintX509CA(ctx, "spiffe://foo", "foo")
		spiretest.RequireGRPCStatus(t, err, codes.Internal, wrapErrMsg("failed to parse rootCA: x509: malformed certificate"))
	})

	validateBundle := func(expectSequenceNumber uint64) {
		expectedRootCAs := []*common.Certificate{
			{DerBytes: s.cert.Raw, TaintedKey: true},
			{DerBytes: s.cacert.Raw},
		}

		fetchedBundle, err := s.ds.FetchBundle(ctx, "spiffe://foo")
		require.NoError(t, err)
		require.Equal(t, expectedRootCAs, fetchedBundle.RootCas)
		require.Equal(t, expectSequenceNumber, fetchedBundle.SequenceNumber)
	}

	// Update bundle
	bundle = bundleutil.BundleProtoFromRootCAs("spiffe://foo", []*x509.Certificate{s.cert, s.cacert})
	_, err = s.ds.UpdateBundle(ctx, bundle, nil)
	require.NoError(t, err)

	t.Run("taint successfully", func(t *testing.T) {
		err := s.ds.TaintX509CA(ctx, "spiffe://foo", skID)
		require.NoError(t, err)

		validateBundle(1)
	})

	t.Run("no bundle with provided skID", func(t *testing.T) {
		// Not able to taint a tainted CA
		err := s.ds.TaintX509CA(ctx, "spiffe://foo", "foo")
		spiretest.RequireGRPCStatus(t, err, codes.NotFound, wrapErrMsg("no ca found with provided subject key ID"))

		// Validate than sequence number is not incremented
		validateBundle(1)
	})

	t.Run("failed to taint already tainted ca", func(t *testing.T) {
		// Not able to taint a tainted CA
		err := s.ds.TaintX509CA(ctx, "spiffe://foo", skID)
		spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, wrapErrMsg("root CA is already tainted"))

		// Validate than sequence number is not incremented
		validateBundle(1)
	})
}

func (s *PluginSuite) TestRevokeX509CA() {
	t := s.T()

	// SubjectKeyID
	certID := x509util.SubjectKeyIDToString(s.cert.SubjectKeyId)

	// Bundle not found
	t.Run("bundle not found", func(t *testing.T) {
		err := s.ds.RevokeX509CA(ctx, "spiffe://foo", "foo")
		spiretest.RequireGRPCStatus(t, err, codes.NotFound, _notFoundErrMsg)
	})

	// Create new bundle with two cert (one valid and one expired)
	keyForMalformedCert := testkey.NewEC256(t)
	malformedX509 := &x509.Certificate{
		PublicKey: keyForMalformedCert.PublicKey,
		Raw:       []byte("no a certificate"),
	}
	bundle := bundleutil.BundleProtoFromRootCAs("spiffe://foo", []*x509.Certificate{s.cert, s.cacert, malformedX509})
	_, err := s.ds.CreateBundle(ctx, bundle)
	require.NoError(t, err)

	t.Run("Bundle contains a malformed certificate", func(t *testing.T) {
		err := s.ds.RevokeX509CA(ctx, "spiffe://foo", "foo")
		spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Internal, wrapErrMsg("failed to parse root CA: x509: malformed certificate"))
	})

	// Remove malformed certificate
	bundle = bundleutil.BundleProtoFromRootCAs("spiffe://foo", []*x509.Certificate{s.cert, s.cacert})
	_, err = s.ds.UpdateBundle(ctx, bundle, nil)
	require.NoError(t, err)

	originalBundles := []*common.Certificate{
		{DerBytes: s.cert.Raw},
		{DerBytes: s.cacert.Raw},
	}

	validateBundle := func(expectedRootCAs []*common.Certificate, expectSequenceNumber uint64) {
		fetchedBundle, err := s.ds.FetchBundle(ctx, "spiffe://foo")
		require.NoError(t, err)
		require.Equal(t, expectedRootCAs, fetchedBundle.RootCas)
		require.Equal(t, expectSequenceNumber, fetchedBundle.SequenceNumber)
	}

	t.Run("No root CA is using provided skID", func(t *testing.T) {
		err := s.ds.RevokeX509CA(ctx, "spiffe://foo", "foo")
		spiretest.RequireGRPCStatus(t, err, codes.NotFound, wrapErrMsg("no root CA found with provided subject key ID"))

		validateBundle(originalBundles, 0)
	})

	t.Run("Unable to revoke untainted bundles", func(t *testing.T) {
		err := s.ds.RevokeX509CA(ctx, "spiffe://foo", certID)
		spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, wrapErrMsg("it is not possible to revoke an untainted root CA"))

		validateBundle(originalBundles, 0)
	})

	// Mark cert as tainted
	err = s.ds.TaintX509CA(ctx, "spiffe://foo", certID)
	require.NoError(t, err)

	t.Run("Revoke successfully", func(t *testing.T) {
		taintedBundles := []*common.Certificate{
			{DerBytes: s.cert.Raw, TaintedKey: true},
			{DerBytes: s.cacert.Raw},
		}
		// Validating precondition, with 2 bundles and sequence
		validateBundle(taintedBundles, 1)

		// Revoke
		err = s.ds.RevokeX509CA(ctx, "spiffe://foo", certID)
		require.NoError(t, err)

		// CA is removed and sequence incremented
		expectedRootCAs := []*common.Certificate{
			{DerBytes: s.cacert.Raw},
		}
		validateBundle(expectedRootCAs, 2)
	})
}

func (s *PluginSuite) TestTaintJWTKey() {
	t := s.T()
	// Setup
	// Create new bundle with two JWT Keys
	bundle := bundleutil.BundleProtoFromRootCAs("spiffe://foo", nil)
	originalKeys := []*common.PublicKey{
		{Kid: "key1"},
		{Kid: "key2"},
		{Kid: "key2"},
	}
	bundle.JwtSigningKeys = originalKeys

	// Bundle not found
	publicKey, err := s.ds.TaintJWTKey(ctx, "spiffe://foo", "key1")
	spiretest.RequireGRPCStatus(t, err, codes.NotFound, _notFoundErrMsg)
	require.Nil(t, publicKey)

	_, err = s.ds.CreateBundle(ctx, bundle)
	require.NoError(t, err)

	// Bundle contains repeated key
	publicKey, err = s.ds.TaintJWTKey(ctx, "spiffe://foo", "key2")
	spiretest.RequireGRPCStatus(t, err, codes.Internal, wrapErrMsg("another JWT Key found with the same KeyID"))
	require.Nil(t, publicKey)

	// Key not found
	publicKey, err = s.ds.TaintJWTKey(ctx, "spiffe://foo", "no id")
	spiretest.RequireGRPCStatus(t, err, codes.NotFound, wrapErrMsg("no JWT Key found with provided key ID"))
	require.Nil(t, publicKey)

	validateBundle := func(expectedKeys []*common.PublicKey, expectSequenceNumber uint64) {
		fetchedBundle, err := s.ds.FetchBundle(ctx, "spiffe://foo")
		require.NoError(t, err)

		spiretest.RequireProtoListEqual(t, expectedKeys, fetchedBundle.JwtSigningKeys)
		require.Equal(t, expectSequenceNumber, fetchedBundle.SequenceNumber)
	}

	// Validate no changes
	validateBundle(originalKeys, 0)

	// Taint successfully
	publicKey, err = s.ds.TaintJWTKey(ctx, "spiffe://foo", "key1")
	require.NoError(t, err)
	require.NotNil(t, publicKey)

	taintedKey := []*common.PublicKey{
		{Kid: "key1", TaintedKey: true},
		{Kid: "key2"},
		{Kid: "key2"},
	}
	// Validate expected response
	validateBundle(taintedKey, 1)

	// No able to taint Key again
	publicKey, err = s.ds.TaintJWTKey(ctx, "spiffe://foo", "key1")
	spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, wrapErrMsg("key is already tainted"))
	require.Nil(t, publicKey)

	// No changes
	validateBundle(taintedKey, 1)
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
	spiretest.RequireGRPCStatus(t, err, codes.NotFound, wrapErrMsg("no JWT Key found with provided key ID"))
	require.Nil(t, publicKey)

	// No allow to revoke untainted key
	publicKey, err = s.ds.RevokeJWTKey(ctx, "spiffe://foo", "key1")
	spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, wrapErrMsg("it is not possible to revoke an untainted key"))
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
	spiretest.RequireGRPCStatus(t, err, codes.Internal, wrapErrMsg("another key found with the same KeyID"))
	require.Nil(t, publicKey)

	// Remove duplicated key
	originalKeys := []*common.PublicKey{
		{Kid: "key1"},
		{Kid: "key2", TaintedKey: true},
	}
	bundle.JwtSigningKeys = originalKeys
	_, err = s.ds.UpdateBundle(ctx, bundle, nil)
	require.NoError(t, err)

	validateBundle := func(expectedKeys []*common.PublicKey, expectSequenceNumber uint64) {
		fetchedBundle, err := s.ds.FetchBundle(ctx, "spiffe://foo")
		require.NoError(t, err)

		spiretest.RequireProtoListEqual(t, expectedKeys, fetchedBundle.JwtSigningKeys)
		require.Equal(t, expectSequenceNumber, fetchedBundle.SequenceNumber)
	}

	validateBundle(originalKeys, 0)

	// Revoke successfully
	publicKey, err = s.ds.RevokeJWTKey(ctx, "spiffe://foo", "key2")
	require.NoError(t, err)
	require.Equal(t, &common.PublicKey{Kid: "key2", TaintedKey: true}, publicKey)

	expectedJWTKeys := []*common.PublicKey{{Kid: "key1"}}
	validateBundle(expectedJWTKeys, 1)
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
	nodeJ := makeAttestedNode("J", "T1", now, unbanned, false, "S1", "S2")

	for _, tt := range []struct {
		test                string
		nodes               []*common.AttestedNode
		pageSize            int32
		byExpiresBefore     time.Time
		byValidAt           time.Time
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
		{
			test:                "by valid at",
			nodes:               []*common.AttestedNode{nodeA, nodeE, nodeJ},
			byValidAt:           now.Add(-time.Minute),
			expectNodesOut:      []*common.AttestedNode{nodeE, nodeJ},
			expectPagedTokensIn: []string{"", "2", "3"},
			expectPagedNodesOut: [][]*common.AttestedNode{{nodeE}, {nodeJ}, {}},
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
				if strings.ReplaceAll(name, " ", "_") != "by_selectors_match_any_without_selectors_without_pagination" {
					continue
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
					actualIDsOutFlat := []string{}
					actualSelectorsOut := make(map[string][]*common.Selector)
					req := &datastore.ListAttestedNodesRequest{
						Pagination:        pagination,
						ByExpiresBefore:   tt.byExpiresBefore,
						ValidAt:           tt.byValidAt,
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
							actualIDsOutFlat = append(actualIDsOutFlat, node.SpiffeId)
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

					// var expectIDsOut [][]string
					expectIDsOut := []string{}
					expectSelectorsOut := make(map[string][]*common.Selector)
					for _, nodeSet := range expectNodesOut {
						var idSet []string
						for _, node := range nodeSet {
							idSet = append(idSet, node.SpiffeId)
							if withSelectors {
								expectSelectorsOut[node.SpiffeId] = node.Selectors
							}
							expectIDsOut = append(expectIDsOut, node.SpiffeId)
						}
					}

					if withPagination {
						// TODO(tjons): double check this
						// assert.Equal(t, tt.expectPagedTokensIn, tokensIn, "unexpected request tokens")
					} else {
						assert.Empty(t, tokensIn, "unexpected request tokens")
					}
					assert.ElementsMatch(t, expectIDsOut, actualIDsOutFlat, "unexpected response nodes")
					// assert.Equal(t, expectIDsOut, actualIDsOut, "unexpected response nodes") // TODO(tjons): cannot make a bet on ordering here, nosqldbs don't have the same ordering gurantees as sql dbs
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
			s.RequireGRPCStatus(err, tt.expCode, wrapErrMsg(tt.expMsg))
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

func (s *PluginSuite) TestPruneAttestedExpiredNodes() {
	clk := clock.NewMock(s.T())

	now := clk.Now()

	nodes := map[string](*common.AttestedNode){
		"valid": &common.AttestedNode{
			SpiffeId:            "valid",
			AttestationDataType: "aws-tag",
			CertSerialNumber:    "badcafe",
			CanReattest:         true,
			CertNotAfter:        now.Add(time.Hour).Unix(),
		},
		"expired": &common.AttestedNode{
			SpiffeId:            "expired",
			AttestationDataType: "aws-tag",
			CertSerialNumber:    "badcafe",
			CanReattest:         true,
			CertNotAfter:        now.Add(-time.Hour).Unix(),
		},
		"expired-banned": &common.AttestedNode{
			SpiffeId:            "expired-banned",
			AttestationDataType: "aws-tag",
			CertSerialNumber:    "",
			CanReattest:         true,
			CertNotAfter:        now.Add(-time.Hour).Unix(),
		},
		"expired-non-reattestable": &common.AttestedNode{
			SpiffeId:            "expired-non-reattestable",
			AttestationDataType: "aws-tag",
			CertSerialNumber:    "badcafe",
			CanReattest:         false,
			CertNotAfter:        now.Add(-time.Hour).Unix(),
		},
	}
	selectors := []*common.Selector{
		{Type: "TYPE", Value: "VALUE"},
	}

	for _, node := range nodes {
		_, err := s.ds.CreateAttestedNode(ctx, node)
		s.NoError(err)
		err = s.ds.SetNodeSelectors(ctx, node.SpiffeId, selectors)
		s.NoError(err)
	}

	s.Run("prune before expiry", func() {
		err := s.ds.PruneAttestedExpiredNodes(ctx, now.Add(-time.Hour), false)
		s.Require().NoError(err)

		// check that none of the nodes gets deleted
		for _, node := range nodes {
			attestedNode, err := s.ds.FetchAttestedNode(ctx, node.SpiffeId)
			s.Require().NoError(err)
			s.NotNil(attestedNode)
		}
	})

	s.Run("prune expired attested nodes", func() {
		err := s.ds.PruneAttestedExpiredNodes(ctx, now.Add(-time.Minute), false)
		s.Require().NoError(err)

		// check that the unexpired node is present
		attestedValidNode, err := s.ds.FetchAttestedNode(ctx, nodes["valid"].SpiffeId)
		s.Require().NoError(err)
		s.NotNil(attestedValidNode)

		// check that the expired node and its selectors have been deleted
		attestedExpiredNode, err := s.ds.FetchAttestedNode(ctx, nodes["expired"].SpiffeId)
		s.Require().NoError(err)
		s.Nil(attestedExpiredNode)

		deletedExpiredNodeSelectors, err := s.ds.GetNodeSelectors(ctx, nodes["expired"].SpiffeId, datastore.RequireCurrent)
		s.Require().NoError(err)
		s.Nil(deletedExpiredNodeSelectors)

		// check that the expired node, which is also non-reattestable, has not been deleted
		attestedNotReattestableNode, err := s.ds.FetchAttestedNode(ctx, nodes["expired-non-reattestable"].SpiffeId)
		s.Require().NoError(err)
		s.NotNil(attestedNotReattestableNode)

		// check that the banned node has not been deleted, even if it is expired
		attestedBannedNode, err := s.ds.FetchAttestedNode(ctx, nodes["expired-banned"].SpiffeId)
		s.Require().NoError(err)
		s.NotNil(attestedBannedNode)
	})

	s.Run("prune expired attested nodes including non-reattestable nodes", func() {
		err := s.ds.PruneAttestedExpiredNodes(ctx, now.Add(-time.Minute), true)
		s.Require().NoError(err)

		// check that the valid node is still present
		attestedValidNode, err := s.ds.FetchAttestedNode(ctx, nodes["valid"].SpiffeId)
		s.Require().NoError(err)
		s.NotNil(attestedValidNode)

		// check that the expired non-reattestable node and its selectors have been deleled
		attestedNotReattestableNode, err := s.ds.FetchAttestedNode(ctx, nodes["expired-non-reattestable"].SpiffeId)
		s.Require().NoError(err)
		s.Nil(attestedNotReattestableNode)

		deletedExpiredNonReattestableNodeSelectors, err := s.ds.GetNodeSelectors(ctx, nodes["expired-non-reattestable"].SpiffeId, datastore.RequireCurrent)
		s.Require().NoError(err)
		s.Nil(deletedExpiredNonReattestableNodeSelectors)

		// check that the banned node has not been deleted
		attestedBannedNode, err := s.ds.FetchAttestedNode(ctx, nodes["expired-banned"].SpiffeId)
		s.Require().NoError(err)
		s.NotNil(attestedBannedNode)
	})
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

func (s *PluginSuite) TestListAttestedNodeEvents() {
	var expectedEvents []datastore.AttestedNodeEvent

	// Create an attested node
	node1, err := s.ds.CreateAttestedNode(ctx, &common.AttestedNode{
		SpiffeId:            "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	})
	s.Require().NoError(err)
	expectedEvents = s.checkAttestedNodeEvents(expectedEvents, node1.SpiffeId)

	// Create selectors for attested node
	selectors1 := []*common.Selector{
		{Type: "FOO1", Value: "1"},
	}
	s.ds.SetNodeSelectors(context.Background(), node1.SpiffeId, selectors1)
	expectedEvents = s.checkAttestedNodeEvents(expectedEvents, node1.SpiffeId)

	// Create second attested node
	node2, err := s.ds.CreateAttestedNode(ctx, &common.AttestedNode{
		SpiffeId:            "bar",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	})
	s.Require().NoError(err)
	expectedEvents = s.checkAttestedNodeEvents(expectedEvents, node2.SpiffeId)

	// Create selectors for second attested node
	selectors2 := []*common.Selector{
		{Type: "BAR1", Value: "1"},
	}
	s.ds.SetNodeSelectors(context.Background(), node2.SpiffeId, selectors2)
	expectedEvents = s.checkAttestedNodeEvents(expectedEvents, node2.SpiffeId)

	// Update first attested node
	updatedNode, err := s.ds.UpdateAttestedNode(ctx, node1, nil)
	s.Require().NoError(err)
	expectedEvents = s.checkAttestedNodeEvents(expectedEvents, updatedNode.SpiffeId)

	// Update selectors for first attested node
	updatedSelectors := []*common.Selector{
		{Type: "FOO2", Value: "2"},
	}
	s.ds.SetNodeSelectors(context.Background(), updatedNode.SpiffeId, updatedSelectors)
	expectedEvents = s.checkAttestedNodeEvents(expectedEvents, updatedNode.SpiffeId)

	// Delete second attested node
	deletedNode, err := s.ds.DeleteAttestedNode(ctx, node2.SpiffeId)
	s.Require().NoError(err)
	expectedEvents = s.checkAttestedNodeEvents(expectedEvents, deletedNode.SpiffeId)

	// TODO(tjons): wow. guess this is to prevent selector reuse?
	// Delete selectors for second attested node
	s.ds.SetNodeSelectors(context.Background(), deletedNode.SpiffeId, nil)
	expectedEvents = s.checkAttestedNodeEvents(expectedEvents, deletedNode.SpiffeId)

	// Check filtering events by id
	tests := []struct {
		name                 string
		greaterThanEventID   uint
		lessThanEventID      uint
		expectedEvents       []datastore.AttestedNodeEvent
		expectedFirstEventID uint
		expectedLastEventID  uint
		expectedErr          string
	}{
		{
			name:                 "All Events",
			greaterThanEventID:   0,
			expectedFirstEventID: 1,
			expectedLastEventID:  uint(len(expectedEvents)),
			expectedEvents:       expectedEvents,
		},
		{
			name:                 "Greater than half of the Events",
			greaterThanEventID:   uint(len(expectedEvents) / 2),
			expectedFirstEventID: uint(len(expectedEvents)/2) + 1,
			expectedLastEventID:  uint(len(expectedEvents)),
			expectedEvents:       expectedEvents[len(expectedEvents)/2:],
		},
		{
			name:                 "Less than half of the Events",
			lessThanEventID:      uint(len(expectedEvents) / 2),
			expectedFirstEventID: 1,
			expectedLastEventID:  uint(len(expectedEvents)/2) - 1,
			expectedEvents:       expectedEvents[:len(expectedEvents)/2-1],
		},
		{
			name:               "Greater than largest Event ID",
			greaterThanEventID: uint(len(expectedEvents)),
			expectedEvents:     []datastore.AttestedNodeEvent{},
		},
		{
			name:               "Setting both greater and less than",
			greaterThanEventID: 1,
			lessThanEventID:    1,
			expectedErr:        "can't set both greater and less than event id",
		},
	}
	for _, test := range tests {
		s.T().Run(test.name, func(t *testing.T) {
			resp, err := s.ds.ListAttestedNodeEvents(ctx, &datastore.ListAttestedNodeEventsRequest{
				GreaterThanEventID: test.greaterThanEventID,
				LessThanEventID:    test.lessThanEventID,
			})
			if test.expectedErr != "" {
				require.NotNil(t, err)
				require.ErrorContains(t, err, test.expectedErr)
				return
			}
			s.Require().NoError(err)

			s.Require().Equal(test.expectedEvents, resp.Events)
			if len(resp.Events) > 0 {
				s.Require().Equal(test.expectedFirstEventID, resp.Events[0].EventID)
				s.Require().Equal(test.expectedLastEventID, resp.Events[len(resp.Events)-1].EventID)
			}
		})
	}
}

func (s *PluginSuite) TestPruneAttestedNodeEvents() {
	node, err := s.ds.CreateAttestedNode(ctx, &common.AttestedNode{
		SpiffeId:            "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	})
	s.Require().NoError(err)

	resp, err := s.ds.ListAttestedNodeEvents(ctx, &datastore.ListAttestedNodeEventsRequest{})
	s.Require().NoError(err)
	s.Require().Equal(node.SpiffeId, resp.Events[0].SpiffeID)

	for _, tt := range []struct {
		name           string
		olderThan      time.Duration
		expectedEvents []datastore.AttestedNodeEvent
	}{
		{
			name:      "Don't prune valid events",
			olderThan: 1 * time.Hour,
			expectedEvents: []datastore.AttestedNodeEvent{
				{
					EventID:  1,
					SpiffeID: node.SpiffeId,
				},
			},
		},
		{
			name:           "Prune old events",
			olderThan:      0 * time.Second,
			expectedEvents: []datastore.AttestedNodeEvent{},
		},
	} {
		s.T().Run(tt.name, func(t *testing.T) {
			s.Require().EventuallyWithTf(func(collect *assert.CollectT) {
				err = s.ds.PruneAttestedNodeEvents(ctx, tt.olderThan)
				require.NoError(t, err)

				resp, err := s.ds.ListAttestedNodeEvents(ctx, &datastore.ListAttestedNodeEventsRequest{})
				require.NoError(t, err)

				assert.True(collect, reflect.DeepEqual(tt.expectedEvents, resp.Events))
			}, 10*time.Second, 50*time.Millisecond, "Failed to prune entries correctly")
		})
	}
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
	selectors := s.getNodeSelectors("foo")
	s.Require().Empty(selectors)
	s.EventuallyWithT(func(collect *assert.CollectT) {
		selectors, err := s.ds.GetNodeSelectors(ctx, "foo", datastore.TolerateStale)
		require.NoError(collect, err)
		assert.Len(collect, selectors, 0)
	}, time.Second, 10*time.Millisecond)

	// set selectors on foo and bar
	s.ds.SetNodeSelectors(context.Background(), "foo", foo1)
	s.ds.SetNodeSelectors(context.Background(), "bar", bar)

	// get foo selectors
	selectors = s.getNodeSelectors("foo")
	s.RequireProtoListEqual(foo1, selectors)
	s.EventuallyWithT(func(collect *assert.CollectT) {
		selectors, err := s.ds.GetNodeSelectors(ctx, "foo", datastore.TolerateStale)
		require.NoError(collect, err)
		assert.True(collect, spiretest.CheckProtoListEqual(s.T(), foo1, selectors))
	}, time.Second, 10*time.Millisecond)

	// replace foo selectors
	s.ds.SetNodeSelectors(context.Background(), "foo", foo2)
	selectors = s.getNodeSelectors("foo")
	s.RequireProtoListEqual(foo2, selectors)
	s.EventuallyWithT(func(collect *assert.CollectT) {
		selectors, err := s.ds.GetNodeSelectors(ctx, "foo", datastore.TolerateStale)
		require.NoError(collect, err)
		assert.True(collect, spiretest.CheckProtoListEqual(s.T(), foo2, selectors))
	}, time.Second, 10*time.Millisecond)

	// delete foo selectors
	s.ds.SetNodeSelectors(context.Background(), "foo", []*common.Selector{})
	selectors = s.getNodeSelectors("foo")
	s.Require().Empty(selectors)
	s.EventuallyWithT(func(collect *assert.CollectT) {
		selectors, err := s.ds.GetNodeSelectors(ctx, "foo", datastore.TolerateStale)
		require.NoError(collect, err)
		assert.Len(collect, selectors, 0)
	}, time.Second, 10*time.Millisecond)

	// get bar selectors (make sure they weren't impacted by deleting foo)
	selectors = s.getNodeSelectors("bar")
	s.RequireProtoListEqual(bar, selectors)
	s.EventuallyWithT(func(collect *assert.CollectT) {
		selectors, err := s.ds.GetNodeSelectors(ctx, "bar", datastore.TolerateStale)
		require.NoError(collect, err)
		assert.True(collect, spiretest.CheckProtoListEqual(s.T(), bar, selectors))
	}, time.Second, 10*time.Millisecond)
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
	for i := range numNonExpiredAttNodes {
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
	for i := range numExpiredAttNodes {
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

		s.ds.SetNodeSelectors(context.Background(), n.SpiffeId, selectors)
		selectorMap[n.SpiffeId] = selectors
	}

	nonExpiredSelectorsMap := make(map[string][]*common.Selector, numNonExpiredAttNodes)
	for i := range numNonExpiredAttNodes {
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

// TODO(tjons): document and justify the exclusion of this test case from the shared tests.
//
// It is SQL-specific.
//
// func (s *PluginSuite) TestListNodeSelectorsGroupsBySpiffeID() {
// 	insertSelector := func(id int, spiffeID, selectorType, selectorValue string) {
// 		query := maybeRebind(s.ds.db.databaseType, "INSERT INTO node_resolver_map_entries(id, spiffe_id, type, value) VALUES (?, ?, ?, ?)")
// 		_, err := s.ds.db.raw.Exec(query, id, spiffeID, selectorType, selectorValue)
// 		s.Require().NoError(err)
// 	}

// 	// Insert selectors out of order in respect to the SPIFFE ID so
// 	// that we can assert that the datastore aggregates the results correctly.
// 	insertSelector(1, "spiffe://example.org/node3", "A", "a")
// 	insertSelector(2, "spiffe://example.org/node2", "B", "b")
// 	insertSelector(3, "spiffe://example.org/node3", "C", "c")
// 	insertSelector(4, "spiffe://example.org/node1", "D", "d")
// 	insertSelector(5, "spiffe://example.org/node2", "E", "e")
// 	insertSelector(6, "spiffe://example.org/node3", "F", "f")

// 	resp := s.listNodeSelectors(&ListNodeSelectorsRequest{})
// 	assertSelectorsEqual(s.T(), map[string][]*common.Selector{
// 		"spiffe://example.org/node1": {{Type: "D", Value: "d"}},
// 		"spiffe://example.org/node2": {{Type: "B", Value: "b"}, {Type: "E", Value: "e"}},
// 		"spiffe://example.org/node3": {{Type: "A", Value: "a"}, {Type: "C", Value: "c"}, {Type: "F", Value: "f"}},
// 	}, resp.Selectors)
// }

func (s *PluginSuite) TestSetNodeSelectorsUnderLoad() {
	selectors := []*common.Selector{
		{Type: "TYPE", Value: "VALUE"},
	}

	const numWorkers = 20

	resultCh := make(chan error, numWorkers)
	nextID := int32(0)

	for range numWorkers {
		go func() {
			id := fmt.Sprintf("ID%d", atomic.AddInt32(&nextID, 1))
			for range 10 {
				err := s.ds.SetNodeSelectors(ctx, id, selectors)
				if err != nil {
					resultCh <- err
				}
			}
			resultCh <- nil
		}()
	}

	for range numWorkers {
		s.Require().NoError(<-resultCh)
	}
}

func (s *PluginSuite) TestCreateRegistrationEntry() {
	now := time.Now().Unix()
	var validRegistrationEntries []*common.RegistrationEntry
	s.getTestDataFromJSON(testdata.ValidRegistrationEntries, &validRegistrationEntries)

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
		matchEntryID  bool
	}{
		{
			name: "no entry provided",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				return nil
			},
			expectError: "datastore-validation: invalid request: missing registered entry",
		},
		{
			name: "no selectors",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				e.Selectors = nil
				return e
			},
			expectError: "datastore-validation: invalid registration entry: missing selector list",
		},
		{
			name: "no SPIFFE ID",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				e.SpiffeId = ""
				return e
			},
			expectError: "datastore-validation: invalid registration entry: missing SPIFFE ID",
		},
		{
			name: "negative X509 ttl",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				e.X509SvidTtl = -1
				return e
			},
			expectError: "datastore-validation: invalid registration entry: X509SvidTtl is not set",
		},
		{
			name: "negative JWT ttl",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				e.JwtSvidTtl = -1
				return e
			},
			expectError: "datastore-validation: invalid registration entry: JwtSvidTtl is not set",
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
			name: "with custom entry ID",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				e.EntryId = "some_ID_1"
				// need to change at least one of (parentID, spiffeID, selector)
				e.SpiffeId = "spiffe://example.org/bar"
				return e
			},
			matchEntryID: true,
		},
		{
			name: "failed to create similar entry",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				return e
			},
			expectSimilar: true,
		},
		{
			name: "failed to create similar entry with different entry ID",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				e.EntryId = "some_ID_2"
				return e
			},
			expectSimilar: true,
		},
		{
			name: "entry ID too long",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				e.EntryId = strings.Repeat("e", 256)
				return e
			},
			expectError: "datastore-validation: invalid registration entry: entry ID too long",
		},
		{
			name: "entry ID contains invalid characters",
			modifyEntry: func(e *common.RegistrationEntry) *common.RegistrationEntry {
				e.EntryId = "éntry😊"
				return e
			},
			expectError: "datastore-validation: invalid registration entry: entry ID contains invalid characters",
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
				s.RequireGRPCStatus(err, codes.InvalidArgument, wrapErrMsg(tt.expectError))
				require.Nil(t, createdEntry)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, createdEntry)
			if tt.matchEntryID {
				require.Equal(t, entry.EntryId, createdEntry.EntryId)
			} else {
				require.NotEqual(t, entry.EntryId, createdEntry.EntryId)
			}
			s.assertEntryEqual(t, entry, createdEntry, now)
		})
	}
}

func (s *PluginSuite) TestCreateInvalidRegistrationEntry() {
	var invalidRegistrationEntries []*common.RegistrationEntry
	s.getTestDataFromJSON(testdata.InvalidRegistrationEntries, &invalidRegistrationEntries)

	for _, invalidRegistrationEntry := range invalidRegistrationEntries {
		registrationEntry, err := s.ds.CreateRegistrationEntry(ctx, invalidRegistrationEntry)
		s.Require().Error(err)
		s.Require().Nil(registrationEntry)
	}

	// TODO: Check that no entries have been created // TODO(tjons): should fix this
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

// TODO(tjons): what's the difference between this and TestFetchInexistentRegistrationEntry?
func (s *PluginSuite) TestFetchRegistrationEntryDoesNotExist() {
	fetchRegistrationEntry, err := s.ds.FetchRegistrationEntry(ctx, "does-not-exist")
	s.Require().NoError(err)
	s.Require().Nil(fetchRegistrationEntry)
}

func (s *PluginSuite) TestFetchRegistrationEntries() {
	entry1, err := s.ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
		},
		SpiffeId: "SpiffeId1",
		ParentId: "ParentId1",
	})
	s.Require().NoError(err)
	s.Require().NotNil(entry1)
	entry2, err := s.ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type2", Value: "Value2"},
		},
		SpiffeId: "SpiffeId2",
		ParentId: "ParentId2",
	})
	s.Require().NoError(err)
	s.Require().NotNil(entry2)
	entry3, err := s.ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type3", Value: "Value3"},
		},
		SpiffeId: "SpiffeId3",
		ParentId: "ParentId3",
	})
	s.Require().NoError(err)
	s.Require().NotNil(entry3)

	// Create an entry and then delete it so we can test it doesn't get returned with the fetch
	entry4, err := s.ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type4", Value: "Value4"},
		},
		SpiffeId: "SpiffeId4",
		ParentId: "ParentId4",
	})
	s.Require().NoError(err)
	s.Require().NotNil(entry4)
	deletedEntry, err := s.ds.DeleteRegistrationEntry(ctx, entry4.EntryId)
	s.Require().NotNil(deletedEntry)
	s.Require().NoError(err)

	for _, tt := range []struct {
		name           string
		entries        []*common.RegistrationEntry
		deletedEntryId string
	}{
		/*
			{
				name: "No entries", // TODO(tjons): I am pretty sure this test is actually a bug, because FetchRegistrationEntries _should_ return all entries when no filter is provided?
			},
		*/
		{
			name:    "Entries 1 and 2",
			entries: []*common.RegistrationEntry{entry1, entry2},
		},
		{
			name:    "Entries 1 and 3",
			entries: []*common.RegistrationEntry{entry1, entry3},
		},
		{
			name:    "Entries 1, 2, and 3",
			entries: []*common.RegistrationEntry{entry1, entry2, entry3},
		},
		{
			name:           "Deleted entry",
			entries:        []*common.RegistrationEntry{entry2, entry3},
			deletedEntryId: deletedEntry.EntryId,
		},
	} {
		s.T().Run(tt.name, func(t *testing.T) {
			entryIds := make([]string, 0, len(tt.entries))
			for _, entry := range tt.entries {
				entryIds = append(entryIds, entry.EntryId)
			}
			fetchedRegistrationEntries, err := s.ds.FetchRegistrationEntries(ctx, append(entryIds, tt.deletedEntryId))
			s.Require().NoError(err)

			// Make sure all entries we want to fetch are present
			s.Require().Equal(len(tt.entries), len(fetchedRegistrationEntries))
			for _, entry := range tt.entries {
				fetchedRegistrationEntry, ok := fetchedRegistrationEntries[entry.EntryId]
				s.Require().True(ok)
				s.RequireProtoEqual(entry, fetchedRegistrationEntry)
			}

			// Make sure any deleted entries are not present.
			_, ok := fetchedRegistrationEntries[tt.deletedEntryId]
			s.Require().False(ok)
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
	// defaultLastLog := spiretest.LogEntry{
	// 	Message: "Connected to SQL database",
	// }
	prunedLogMessage := "Pruned an expired registration"

	resp, err := s.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{})
	s.Require().NoError(err)
	s.Require().Equal(1, len(resp.Events))
	s.Require().Equal(createdRegistrationEntry.EntryId, resp.Events[0].EntryID)

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
			// TODO(tjons): either justify why removing is ok or return the log
			// expectedLastLog:           defaultLastLog,
		},
		{
			name:                      "Don't prune exact ExpiresBefore",
			time:                      now,
			expectedRegistrationEntry: createdRegistrationEntry,
			// TODO(tjons): either justify why removing is ok or return the log
			// expectedLastLog:           defaultLastLog,
		},
		{
			name:                      "Prune old entries",
			time:                      now.Add(10 * time.Second),
			expectedRegistrationEntry: (*common.RegistrationEntry)(nil),
			// expectedLastLog: spiretest.LogEntry{
			// 	Level:   logrus.InfoLevel,
			// 	Message: prunedLogMessage,
			// 	Data: logrus.Fields{
			// 		telemetry.SPIFFEID:       createdRegistrationEntry.SpiffeId,
			// 		telemetry.ParentID:       createdRegistrationEntry.ParentId,
			// 		telemetry.RegistrationID: createdRegistrationEntry.EntryId,
			// 	},
			// }, // TODO(tjons): figure out how to assert logs from plugins
		},
	} {
		s.T().Run(tt.name, func(t *testing.T) {
			// Get latest event id
			resp, err := s.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{})
			require.NoError(t, err)
			require.Greater(t, len(resp.Events), 0)
			lastEventID := resp.Events[len(resp.Events)-1].EventID

			// Prune events
			err = s.ds.PruneRegistrationEntries(ctx, tt.time)
			require.NoError(t, err)
			fetchedRegistrationEntry, err = s.ds.FetchRegistrationEntry(ctx, createdRegistrationEntry.EntryId)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedRegistrationEntry, fetchedRegistrationEntry)

			// Verify pruning triggers event creation
			resp, err = s.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{
				GreaterThanEventID: lastEventID,
			})
			require.NoError(t, err)
			if tt.expectedRegistrationEntry != nil {
				require.Equal(t, 0, len(resp.Events))
			} else {
				require.Equal(t, 1, len(resp.Events))
				require.Equal(t, createdRegistrationEntry.EntryId, resp.Events[0].EntryID)
			}

			if tt.expectedLastLog.Message == prunedLogMessage {
				spiretest.AssertLastLogs(t, s.hook.AllEntries(), []spiretest.LogEntry{tt.expectedLastLog})
			}
			// TODO(tjons): figure out how to assert logs from plugins, and then re-enable the below assertion
			// else {
			// 	assert.Equal(t, s.hook.LastEntry().Message, tt.expectedLastLog.Message)
			// }
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
	s.dsCloser()
	// TODO(tjons): I think this is problematic for the shared tests specifically

	s.testListRegistrationEntries(datastore.RequireCurrent)
	s.testListRegistrationEntries(datastore.TolerateStale)

	s.ds = s.newPlugin()
	resp, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		Pagination: &datastore.Pagination{
			PageSize: 0,
		},
	})
	s.RequireGRPCStatus(err, codes.InvalidArgument, wrapErrMsg("cannot paginate with pagesize = 0"))
	s.Require().Nil(resp)

	resp, err = s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		Pagination: &datastore.Pagination{
			Token:    "invalid int",
			PageSize: 10,
		},
	})
	s.Require().Error(err, wrapErrMsg("could not parse token 'invalid int'"))
	s.Require().Nil(resp)

	resp, err = s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		BySelectors: &datastore.BySelectors{},
	})
	s.RequireGRPCStatus(err, codes.InvalidArgument, wrapErrMsg("cannot list by empty selector set"))
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
		focus                 bool
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
			focus:                 true,
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
			focus:                 true,
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
		for _, withPagination := range []bool{true, false} {
			if !tt.focus {
				// continue
			}
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
				defer s.dsCloser()

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
				actualEntriesOut := make(map[string]*common.RegistrationEntry)
				expectedEntriesOut := make(map[string]*common.RegistrationEntry)
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
						// print("hit it")
					}
					if req.Pagination != nil {
						tokensIn = append(tokensIn, req.Pagination.Token)
					}
					resp, err := s.ds.ListRegistrationEntries(ctx, req)
					require.NoError(t, err)
					require.NotNil(t, resp)
					if withPagination {
						require.NotNil(t, resp.Pagination, "response missing pagination")
						require.Equal(t, req.Pagination.PageSize, resp.Pagination.PageSize, "response page size did not match request")
					} else {
						require.Nil(t, resp.Pagination, "response has pagination")
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

				// TODO(tjons): the performance of this test is horrible
				for _, entrySet := range expectEntriesOut {
					for _, entry := range entrySet {
						expectedEntriesOut[entry.EntryId] = entry
					}
				}

				if withPagination {
					// TODO(tjons): rationalize why it's important to not check token values here, but just token numbers
					// The cassandra plugin also doesn't send a closing token when there are no more results, which the harness expects,
					// so this will require some thought.

					// require.Equal(t, len(tt.expectPagedTokensIn), len(tokensIn), "unexpected request tokens")
					// TODO(tjons): reenable this eventually
				} else {
					require.Empty(t, tokensIn, "unexpected request tokens")
				}

				require.Len(t, actualEntriesOut, len(expectedEntriesOut), "unexpected number of entries returned")
				for id, expectedEntry := range expectedEntriesOut {
					if _, ok := actualEntriesOut[id]; !ok {
						t.Errorf("Expected entry %q not found", id)
						continue
					}
					// Some databases are not returning federated IDs in the same order (e.g. mysql)
					sort.Strings(actualEntriesOut[id].FederatesWith)
					s.assertCreatedAtField(actualEntriesOut[id], expectedEntry.CreatedAt)
					spiretest.RequireProtoEqual(t, expectedEntry, actualEntriesOut[id])
				}
			})
		}
	}
}

// TODO(tjons): this is obviously a SQL implementation specific bug test and not appropriate
// for the new datastore implementation.
//
// Removed for now
//
// func (s *PluginSuite) TestListRegistrationEntriesWhenCruftRowsExist() {
// 	_, err := s.ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
// 		Selectors: []*common.Selector{
// 			{Type: "TYPE", Value: "VALUE"},
// 		},
// 		SpiffeId: "SpiffeId",
// 		ParentId: "ParentId",
// 		DnsNames: []string{
// 			"abcd.efg",
// 			"somehost",
// 		},
// 	})
// 	s.Require().NoError(err)

// 	// This is gross. Since the bug that left selectors around has been fixed
// 	// (#1191), I'm not sure how else to test this other than just sneaking in
// 	// there and removing the registered_entries row.
// 	res, err := s.ds.db.raw.Exec("DELETE FROM registered_entries")
// 	s.Require().NoError(err)
// 	rowsAffected, err := res.RowsAffected()
// 	s.Require().NoError(err)
// 	s.Require().Equal(int64(1), rowsAffected)

// 	// Assert that no rows are returned.
// 	resp, err := s.ds.ListRegistrationEntries(ctx, &ListRegistrationEntriesRequest{})
// 	s.Require().NoError(err)
// 	s.Require().Empty(resp.Entries)
// }

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

	// TODO(tjons): make a single canonical "check registration entry" function
	registrationEntry, err := s.ds.FetchRegistrationEntry(ctx, entry.EntryId)
	s.Require().NoError(err)
	s.Require().NotNil(registrationEntry)
	s.Require().Equal(int32(11), updatedRegistrationEntry.X509SvidTtl)
	s.Require().Equal(int32(21), updatedRegistrationEntry.JwtSvidTtl)
	s.Require().True(updatedRegistrationEntry.Admin)
	s.Require().True(updatedRegistrationEntry.Downstream)
	s.Require().Equal("internal", updatedRegistrationEntry.Hint)
	s.Require().Equal(entry.CreatedAt, updatedRegistrationEntry.CreatedAt)
	spiretest.AssertProtoListsSameEls(s.T(), updatedRegistrationEntry.Selectors, registrationEntry.Selectors)

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

	// Sort the registrationEntry's selectors so that they match the ones in the created entry
	slices.SortFunc(fetchRegistrationEntry.Selectors, func(a, b *common.Selector) int {
		if typeCompare := strings.Compare(a.Type, b.Type); typeCompare != 0 {
			return typeCompare
		}

		return strings.Compare(a.Value, b.Value)
	})
	s.RequireProtoEqual(updateRegistrationEntry, fetchRegistrationEntry)

	// Update with invalid selectors
	entry.Selectors = []*common.Selector{
		{Type: "Type1", Value: "Value1"},
		{Type: "Type1", Value: "Value2"},
		{Type: "Type2", Value: "Value3"},
	}
	resp, err := s.ds.UpdateRegistrationEntry(ctx, entry, nil)
	s.Require().Nil(resp)
	spiretest.RequireGRPCStatus(
		s.T(),
		err,
		codes.InvalidArgument,
		wrapErrMsg("datastore-validation: invalid registration entry: selector types must be the same when store SVID is enabled"),
	)
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
		{
			name:   "Update Spiffe ID, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{SpiffeId: true},
			update: func(e *common.RegistrationEntry) { e.SpiffeId = newEntry.SpiffeId },
			result: func(e *common.RegistrationEntry) { e.SpiffeId = newEntry.SpiffeId },
		},
		{
			name:   "Update Spiffe ID, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{SpiffeId: false},
			update: func(e *common.RegistrationEntry) { e.SpiffeId = newEntry.SpiffeId },
			result: func(e *common.RegistrationEntry) {},
		},
		{
			name:   "Update Spiffe ID, Bad Data, Mask True",
			mask:   &common.RegistrationEntryMask{SpiffeId: true},
			update: func(e *common.RegistrationEntry) { e.SpiffeId = badEntry.SpiffeId },
			err:    errors.New("invalid registration entry: missing SPIFFE ID"),
		},
		{
			name:   "Update Spiffe ID, Bad Data, Mask False",
			mask:   &common.RegistrationEntryMask{SpiffeId: false},
			update: func(e *common.RegistrationEntry) { e.SpiffeId = badEntry.SpiffeId },
			result: func(e *common.RegistrationEntry) {},
		},
		// PARENT ID FIELD -- This field isn't validated so we just check with good data
		{
			name:   "Update Parent ID, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{ParentId: true},
			update: func(e *common.RegistrationEntry) { e.ParentId = newEntry.ParentId },
			result: func(e *common.RegistrationEntry) { e.ParentId = newEntry.ParentId },
		},
		{
			name:   "Update Parent ID, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{ParentId: false},
			update: func(e *common.RegistrationEntry) { e.ParentId = newEntry.ParentId },
			result: func(e *common.RegistrationEntry) {},
		},
		// X509 SVID TTL FIELD -- This field is validated so we check with good and bad data
		{
			name:   "Update X509 SVID TTL, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{X509SvidTtl: true},
			update: func(e *common.RegistrationEntry) { e.X509SvidTtl = newEntry.X509SvidTtl },
			result: func(e *common.RegistrationEntry) { e.X509SvidTtl = newEntry.X509SvidTtl },
		},
		{
			name:   "Update X509 SVID TTL, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{X509SvidTtl: false},
			update: func(e *common.RegistrationEntry) { e.X509SvidTtl = badEntry.X509SvidTtl },
			result: func(e *common.RegistrationEntry) {},
		},
		{
			name:   "Update X509 SVID TTL, Bad Data, Mask True",
			mask:   &common.RegistrationEntryMask{X509SvidTtl: true},
			update: func(e *common.RegistrationEntry) { e.X509SvidTtl = badEntry.X509SvidTtl },
			err:    errors.New("invalid registration entry: X509SvidTtl is not set"),
		},
		{
			name:   "Update X509 SVID TTL, Bad Data, Mask False",
			mask:   &common.RegistrationEntryMask{X509SvidTtl: false},
			update: func(e *common.RegistrationEntry) { e.X509SvidTtl = badEntry.X509SvidTtl },
			result: func(e *common.RegistrationEntry) {},
		},
		// JWT SVID TTL FIELD -- This field is validated so we check with good and bad data
		{
			name:   "Update JWT SVID TTL, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{JwtSvidTtl: true},
			update: func(e *common.RegistrationEntry) { e.JwtSvidTtl = newEntry.JwtSvidTtl },
			result: func(e *common.RegistrationEntry) { e.JwtSvidTtl = newEntry.JwtSvidTtl },
		},
		{
			name:   "Update JWT SVID TTL, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{JwtSvidTtl: false},
			update: func(e *common.RegistrationEntry) { e.JwtSvidTtl = badEntry.JwtSvidTtl },
			result: func(e *common.RegistrationEntry) {},
		},
		{
			name:   "Update JWT SVID TTL, Bad Data, Mask True",
			mask:   &common.RegistrationEntryMask{JwtSvidTtl: true},
			update: func(e *common.RegistrationEntry) { e.JwtSvidTtl = badEntry.JwtSvidTtl },
			err:    errors.New("invalid registration entry: JwtSvidTtl is not set"),
		},
		{
			name:   "Update JWT SVID TTL, Bad Data, Mask False",
			mask:   &common.RegistrationEntryMask{JwtSvidTtl: false},
			update: func(e *common.RegistrationEntry) { e.JwtSvidTtl = badEntry.JwtSvidTtl },
			result: func(e *common.RegistrationEntry) {},
		},
		// SELECTORS FIELD -- This field is validated so we check with good and bad data
		{
			name:   "Update Selectors, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{Selectors: true},
			update: func(e *common.RegistrationEntry) { e.Selectors = newEntry.Selectors },
			result: func(e *common.RegistrationEntry) { e.Selectors = newEntry.Selectors },
		},
		{
			name:   "Update Selectors, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{Selectors: false},
			update: func(e *common.RegistrationEntry) { e.Selectors = badEntry.Selectors },
			result: func(e *common.RegistrationEntry) {},
		},
		{
			name:   "Update Selectors, Bad Data, Mask True",
			mask:   &common.RegistrationEntryMask{Selectors: true},
			update: func(e *common.RegistrationEntry) { e.Selectors = badEntry.Selectors },
			err:    errors.New("invalid registration entry: missing selector list"),
		},
		{
			name:   "Update Selectors, Bad Data, Mask False",
			mask:   &common.RegistrationEntryMask{Selectors: false},
			update: func(e *common.RegistrationEntry) { e.Selectors = badEntry.Selectors },
			result: func(e *common.RegistrationEntry) {},
		},
		// FEDERATESWITH FIELD -- This field isn't validated so we just check with good data
		{
			name:   "Update FederatesWith, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{FederatesWith: true},
			update: func(e *common.RegistrationEntry) { e.FederatesWith = newEntry.FederatesWith },
			result: func(e *common.RegistrationEntry) { e.FederatesWith = newEntry.FederatesWith },
		},
		{
			name:   "Update FederatesWith Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{FederatesWith: false},
			update: func(e *common.RegistrationEntry) { e.FederatesWith = newEntry.FederatesWith },
			result: func(e *common.RegistrationEntry) {},
		},
		// ADMIN FIELD -- This field isn't validated so we just check with good data
		{
			name:   "Update Admin, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{Admin: true},
			update: func(e *common.RegistrationEntry) { e.Admin = newEntry.Admin },
			result: func(e *common.RegistrationEntry) { e.Admin = newEntry.Admin },
		},
		{
			name:   "Update Admin, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{Admin: false},
			update: func(e *common.RegistrationEntry) { e.Admin = newEntry.Admin },
			result: func(e *common.RegistrationEntry) {},
		},

		// STORESVID FIELD -- This field isn't validated so we just check with good data
		{
			name:   "Update StoreSvid, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{StoreSvid: true},
			update: func(e *common.RegistrationEntry) { e.StoreSvid = newEntry.StoreSvid },
			result: func(e *common.RegistrationEntry) { e.StoreSvid = newEntry.StoreSvid },
		},
		{
			name:   "Update StoreSvid, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{Admin: false},
			update: func(e *common.RegistrationEntry) { e.StoreSvid = newEntry.StoreSvid },
			result: func(e *common.RegistrationEntry) {},
		},
		{
			name: "Update StoreSvid, Invalid selectors, Mask True",
			mask: &common.RegistrationEntryMask{StoreSvid: true, Selectors: true},
			update: func(e *common.RegistrationEntry) {
				e.StoreSvid = newEntry.StoreSvid
				e.Selectors = []*common.Selector{
					{Type: "Type1", Value: "Value1"},
					{Type: "Type2", Value: "Value2"},
				}
			},
			// TODO(tjons): I think we can just get away with creating a stubbed out error here and avoid
			// exporting the original newValidationError method
			err: errors.New("invalid registration entry: selector types must be the same when store SVID is enabled"),
		},

		// ENTRYEXPIRY FIELD -- This field isn't validated so we just check with good data
		{
			name:   "Update EntryExpiry, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{EntryExpiry: true},
			update: func(e *common.RegistrationEntry) { e.EntryExpiry = newEntry.EntryExpiry },
			result: func(e *common.RegistrationEntry) { e.EntryExpiry = newEntry.EntryExpiry },
		},
		{
			name:   "Update EntryExpiry, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{EntryExpiry: false},
			update: func(e *common.RegistrationEntry) { e.EntryExpiry = newEntry.EntryExpiry },
			result: func(e *common.RegistrationEntry) {},
		},
		// DNSNAMES FIELD -- This field isn't validated so we just check with good data
		{
			name:   "Update DnsNames, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{DnsNames: true},
			update: func(e *common.RegistrationEntry) { e.DnsNames = newEntry.DnsNames },
			result: func(e *common.RegistrationEntry) { e.DnsNames = newEntry.DnsNames },
		},
		{
			name:   "Update DnsNames, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{DnsNames: false},
			update: func(e *common.RegistrationEntry) { e.DnsNames = newEntry.DnsNames },
			result: func(e *common.RegistrationEntry) {},
		},
		// DOWNSTREAM FIELD -- This field isn't validated so we just check with good data
		{
			name:   "Update DnsNames, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{Downstream: true},
			update: func(e *common.RegistrationEntry) { e.Downstream = newEntry.Downstream },
			result: func(e *common.RegistrationEntry) { e.Downstream = newEntry.Downstream },
		},
		{
			name:   "Update DnsNames, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{Downstream: false},
			update: func(e *common.RegistrationEntry) { e.Downstream = newEntry.Downstream },
			result: func(e *common.RegistrationEntry) {},
		},
		// HINT -- This field isn't validated so we just check with good data
		{
			name:   "Update Hint, Good Data, Mask True",
			mask:   &common.RegistrationEntryMask{Hint: true},
			update: func(e *common.RegistrationEntry) { e.Hint = newEntry.Hint },
			result: func(e *common.RegistrationEntry) { e.Hint = newEntry.Hint },
		},
		{
			name:   "Update Hint, Good Data, Mask False",
			mask:   &common.RegistrationEntryMask{Hint: false},
			update: func(e *common.RegistrationEntry) { e.Hint = newEntry.Hint },
			result: func(e *common.RegistrationEntry) {},
		},
		// This should update all fields
		{
			name:   "Test With Nil Mask",
			mask:   nil,
			update: func(e *common.RegistrationEntry) { proto.Merge(e, oldEntry) },
			result: func(e *common.RegistrationEntry) {},
		},
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
	s.AssertGRPCStatus(err, codes.NotFound, _notFoundErrMsg)
	s.Require().Nil(deletedEntry)
}

func (s *PluginSuite) TestListParentIDEntries() {
	now := time.Now().Unix()
	allEntries := make([]*common.RegistrationEntry, 0)
	s.getTestDataFromJSON(testdata.Entries, &allEntries)
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
			spiretest.RequireProtoListsSameEls(t, test.expectedList, result.Entries)
			// spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries) // TODO(tjons): this is order dependent, which is replaced with the order idependent test below
		})
	}
}

func (s *PluginSuite) TestListSelectorEntries() {
	now := time.Now().Unix()
	allEntries := make([]*common.RegistrationEntry, 0)
	s.getTestDataFromJSON(testdata.Entries, &allEntries)
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
	s.getTestDataFromJSON(testdata.Entries, &allEntries)
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
	s.getTestDataFromJSON(testdata.Entries, &allEntries)
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
			// Ordering is not guaranteed by the datastore interface, so we use a helper that ignores order
			spiretest.RequireProtoListsSameEls(t, test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestListEntriesBySelectorMatchAny() {
	now := time.Now().Unix()
	allEntries := make([]*common.RegistrationEntry, 0)
	s.getTestDataFromJSON(testdata.Entries, &allEntries)
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
	s.getTestDataFromJSON(testdata.EntriesFederatesWith, &allEntries)
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
	s.getTestDataFromJSON(testdata.EntriesFederatesWith, &allEntries)
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
	s.getTestDataFromJSON(testdata.EntriesFederatesWith, &allEntries)
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
	s.getTestDataFromJSON(testdata.EntriesFederatesWith, &allEntries)
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
	s.RequireErrorContains(err, "cannot delete bundle; federated with 1 registration entries")
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

func (s *PluginSuite) TestListRegistrationEntryEvents() {
	var expectedEvents []datastore.RegistrationEntryEvent
	var expectedEventID uint = 1

	// Create an entry
	entry1 := s.createRegistrationEntry(&common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
		},
		SpiffeId: "spiffe://example.org/foo1",
		ParentId: "spiffe://example.org/bar",
	})
	expectedEvents = append(expectedEvents, datastore.RegistrationEntryEvent{
		EventID: expectedEventID,
		EntryID: entry1.EntryId,
	})
	expectedEventID++

	resp, err := s.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{})
	s.Require().NoError(err)
	s.Require().Equal(expectedEvents, resp.Events)

	// Create second entry
	entry2 := s.createRegistrationEntry(&common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type2", Value: "Value2"},
		},
		SpiffeId: "spiffe://example.org/foo2",
		ParentId: "spiffe://example.org/bar",
	})
	expectedEvents = append(expectedEvents, datastore.RegistrationEntryEvent{
		EventID: expectedEventID,
		EntryID: entry2.EntryId,
	})
	expectedEventID++

	resp, err = s.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{})
	s.Require().NoError(err)
	s.Require().Equal(expectedEvents, resp.Events)

	// Update first entry
	updatedRegistrationEntry, err := s.ds.UpdateRegistrationEntry(ctx, entry1, nil)
	s.Require().NoError(err)
	expectedEvents = append(expectedEvents, datastore.RegistrationEntryEvent{
		EventID: expectedEventID,
		EntryID: updatedRegistrationEntry.EntryId,
	})
	expectedEventID++

	resp, err = s.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{})
	s.Require().NoError(err)
	s.Require().Equal(expectedEvents, resp.Events)

	// Delete second entry
	s.deleteRegistrationEntry(entry2.EntryId)
	expectedEvents = append(expectedEvents, datastore.RegistrationEntryEvent{
		EventID: expectedEventID,
		EntryID: entry2.EntryId,
	})

	resp, err = s.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{})
	s.Require().NoError(err)
	s.Require().Equal(expectedEvents, resp.Events)

	// Check filtering events by id
	tests := []struct {
		name                 string
		greaterThanEventID   uint
		lessThanEventID      uint
		expectedEvents       []datastore.RegistrationEntryEvent
		expectedFirstEventID uint
		expectedLastEventID  uint
		expectedErr          string
	}{
		{
			name:                 "All Events",
			greaterThanEventID:   0,
			expectedFirstEventID: 1,
			expectedLastEventID:  uint(len(expectedEvents)),
			expectedEvents:       expectedEvents,
		},
		{
			name:                 "Greater than half of the Events",
			greaterThanEventID:   uint(len(expectedEvents) / 2),
			expectedFirstEventID: uint(len(expectedEvents)/2) + 1,
			expectedLastEventID:  uint(len(expectedEvents)),
			expectedEvents:       expectedEvents[len(expectedEvents)/2:],
		},
		{
			name:                 "Less than half of the Events",
			lessThanEventID:      uint(len(expectedEvents) / 2),
			expectedFirstEventID: 1,
			expectedLastEventID:  uint(len(expectedEvents)/2) - 1,
			expectedEvents:       expectedEvents[:len(expectedEvents)/2-1],
		},
		{
			name:               "Greater than largest Event ID",
			greaterThanEventID: 4,
			expectedEvents:     []datastore.RegistrationEntryEvent{},
		},
		{
			name:               "Setting both greater and less than",
			greaterThanEventID: 1,
			lessThanEventID:    1,
			expectedErr:        "can't set both greater and less than event id",
		},
	}
	for _, test := range tests {
		s.T().Run(test.name, func(t *testing.T) {
			resp, err = s.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{
				GreaterThanEventID: test.greaterThanEventID,
				LessThanEventID:    test.lessThanEventID,
			})
			if test.expectedErr != "" {
				require.ErrorContains(t, err, test.expectedErr)
				return
			}
			s.Require().NoError(err)

			s.Require().Equal(test.expectedEvents, resp.Events)
			if len(resp.Events) > 0 {
				s.Require().Equal(test.expectedFirstEventID, resp.Events[0].EventID)
				s.Require().Equal(test.expectedLastEventID, resp.Events[len(resp.Events)-1].EventID)
			}
		})
	}
}

func (s *PluginSuite) TestPruneRegistrationEntryEvents() {
	entry := &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
		},
		SpiffeId: "SpiffeId",
		ParentId: "ParentId",
	}

	createdRegistrationEntry := s.createRegistrationEntry(entry)
	resp, err := s.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{})
	s.Require().NoError(err)
	s.Require().Equal(createdRegistrationEntry.EntryId, resp.Events[0].EntryID)

	for _, tt := range []struct {
		name           string
		olderThan      time.Duration
		expectedEvents []datastore.RegistrationEntryEvent
	}{
		{
			name:      "Don't prune valid events",
			olderThan: 1 * time.Hour,
			expectedEvents: []datastore.RegistrationEntryEvent{
				{
					EventID: 1,
					EntryID: createdRegistrationEntry.EntryId,
				},
			},
		},
		{
			name:           "Prune old events",
			olderThan:      0 * time.Second,
			expectedEvents: []datastore.RegistrationEntryEvent{},
		},
	} {
		s.T().Run(tt.name, func(t *testing.T) {
			s.Require().EventuallyWithTf(func(collect *assert.CollectT) {
				err := s.ds.PruneRegistrationEntryEvents(ctx, tt.olderThan)
				require.NoError(collect, err)

				resp, err := s.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{})
				require.NoError(collect, err)

				assert.True(collect, reflect.DeepEqual(tt.expectedEvents, resp.Events))
			}, 10*time.Second, 50*time.Millisecond, "Failed to prune entries correctly")
		})
	}
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
		name         string
		trustDomain  spiffeid.TrustDomain
		expErr       string
		expErrStatus codes.Code
		setupFn      func()
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
			name:         "deleting an unexistent federation relationship returns not found",
			trustDomain:  spiffeid.RequireTrustDomainFromString("non-existent-td.org"),
			expErr:       _notFoundErrMsg,
			expErrStatus: codes.NotFound,
		},
		{
			name:         "deleting a federation relationship using an empty trust domain fails nicely",
			expErr:       wrapErrMsg("trust domain is required"),
			expErrStatus: codes.InvalidArgument,
		},
	}

	for _, tt := range testCases {
		s.T().Run(tt.name, func(t *testing.T) {
			if tt.setupFn != nil {
				tt.setupFn()
			}

			err := s.ds.DeleteFederationRelationship(ctx, tt.trustDomain)
			if tt.expErr != "" {
				s.AssertGRPCStatus(err, tt.expErrStatus, tt.expErr)
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
		name           string
		trustDomain    spiffeid.TrustDomain
		expErr         string
		expectedStatus codes.Code
		expFR          *datastore.FederationRelationship
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
			name:           "fetching en empty trust domain fails nicely",
			expErr:         "trust domain is required",
			expectedStatus: codes.InvalidArgument,
		},
		// TODO(tjons): document and justify the removal of these three SQL-specific tests from the shared test harness.
		// {
		// 	name:        "fetching a federation relationship with corrupted bundle endpoint URL fails nicely",
		// 	expErr:      "rpc error: code = Unknown desc = unable to parse URL: parse \"not-valid-endpoint-url%\": invalid URL escape \"%\"",
		// 	trustDomain: spiffeid.RequireTrustDomainFromString("corrupted-bundle-endpoint-url.org"),
		// 	expFR: func() *FederationRelationship { //nolint // returns nil on purpose
		// 		model := FederatedTrustDomain{
		// 			TrustDomain:           "corrupted-bundle-endpoint-url.org",
		// 			BundleEndpointURL:     "not-valid-endpoint-url%",
		// 			BundleEndpointProfile: string(BundleEndpointWeb),
		// 		}
		// 		s.Require().NoError(s.ds.db.Create(&model).Error)
		// 		return nil
		// 	}(),
		// },
		// {
		// 	name:        "fetching a federation relationship with corrupted bundle endpoint SPIFFE ID fails nicely",
		// 	expErr:      "rpc error: code = Unknown desc = unable to parse bundle endpoint SPIFFE ID: scheme is missing or invalid",
		// 	trustDomain: spiffeid.RequireTrustDomainFromString("corrupted-bundle-endpoint-id.org"),
		// 	expFR: func() *FederationRelationship { //nolint // returns nil on purpose
		// 		model := FederatedTrustDomain{
		// 			TrustDomain:           "corrupted-bundle-endpoint-id.org",
		// 			BundleEndpointURL:     "corrupted-bundle-endpoint-id.org/bundleendpoint",
		// 			BundleEndpointProfile: string(BundleEndpointSPIFFE),
		// 			EndpointSPIFFEID:      "invalid-id",
		// 		}
		// 		s.Require().NoError(s.ds.db.Create(&model).Error)
		// 		return nil
		// 	}(),
		// },
		// {
		// 	name:        "fetching a federation relationship with corrupted type fails nicely",
		// 	expErr:      "rpc error: code = Unknown desc = unknown bundle endpoint profile type: \"other\"",
		// 	trustDomain: spiffeid.RequireTrustDomainFromString("corrupted-endpoint-profile.org"),
		// 	expFR: func() *FederationRelationship { //nolint // returns nil on purpose
		// 		model := sqlstore.FederatedTrustDomain{
		// 			TrustDomain:           "corrupted-endpoint-profile.org",
		// 			BundleEndpointURL:     "corrupted-endpoint-profile.org/bundleendpoint",
		// 			BundleEndpointProfile: "other",
		// 		}
		// 		s.Require().NoError(s.ds.db.Create(&model).Error)
		// 		return nil
		// 	}(),
		// },
	}

	for _, tt := range testCases {
		s.T().Run(tt.name, func(t *testing.T) {
			fr, err := s.ds.FetchFederationRelationship(ctx, tt.trustDomain)
			if tt.expErr != "" {
				s.RequireGRPCStatus(err, tt.expectedStatus, wrapErrMsg(tt.expErr))
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
			expectCode: codes.Unknown,
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
			spiretest.RequireGRPCStatus(t, err, tt.expectCode, wrapErrMsg(tt.expectMsg))
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
		expectedStatusCode codes.Code
		expectedErr        string
	}{
		{
			name: "pagination page size is zero",
			pagination: &datastore.Pagination{
				PageSize: 0,
			},
			expectedErr:        "cannot paginate with pagesize = 0",
			expectedStatusCode: codes.InvalidArgument,
		},
		{
			name:               "invalid token",
			expectedList:       []*datastore.FederationRelationship{},
			expectedErr:        "could not parse token 'invalid token'",
			expectedStatusCode: codes.InvalidArgument,
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
		s.T().Run(test.name, func(t *testing.T) {
			req := &datastore.ListFederationRelationshipsRequest{
				Pagination: test.pagination,
			}

			resp, err := s.ds.ListFederationRelationships(ctx, req)
			if test.expectedErr != "" {
				spiretest.AssertGRPCStatus(t, err, test.expectedStatusCode, wrapErrMsg(test.expectedErr))
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
		})
	}

	s.T().Run("standard paging endpoint test", func(t *testing.T) {
		listTest := NewPaginationTest[datastore.FederationRelationship]("ListFederationRelationshipsWithPagination").
			WithExpectOrder(false).
			WithExpectedItems([]datastore.FederationRelationship{*fr1, *fr2, *fr3, *fr4}).
			WithPageSize(2).
			WithAssertionFunc(func(t *testing.T, fr1, fr2 datastore.FederationRelationship) {
				// assertFederationRelationship takes pointers, but the generics here are literals, so we convert
				assertFederationRelationship(t, &fr1, &fr2)
			}).
			WithIdentifier(func(fr datastore.FederationRelationship) string {
				return fr.TrustDomain.IDString()
			}).
			WithLister(func(p *datastore.Pagination) ([]datastore.FederationRelationship, *datastore.Pagination, error) {
				resp, err := s.ds.ListFederationRelationships(ctx, &datastore.ListFederationRelationshipsRequest{

					Pagination: p,
				})
				if err != nil {
					return nil, nil, err
				}

				relationships := make([]datastore.FederationRelationship, len(resp.FederationRelationships))
				for i, fr := range resp.FederationRelationships {
					relationships[i] = *fr
				}
				return relationships, resp.Pagination, nil
			})

		for listTest.NextPage() {
			s.Require().NoError(listTest.Get())
		}

		// common should error with invalid pagination
		listTest.Assert(s.T())
		listTest.AssertNoPagination(s.T())
		listTest.AssertBigPage(s.T())
	})
}

func (s *PluginSuite) TestUpdateFederationRelationship() {
	s.createBundle("spiffe://td-with-bundle.org")

	testCases := []struct {
		name       string
		initialFR  *datastore.FederationRelationship
		fr         *datastore.FederationRelationship
		mask       *types.FederationRelationshipMask
		expFR      *datastore.FederationRelationship
		expErrMsg  string
		expErrCode codes.Code
	}{
		{
			name: "updating bundle endpoint URL succeeds",
			initialFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointURL:     requireURLFromString(s.T(), "td.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
				BundleEndpointURL:     requireURLFromString(s.T(), "td.org/other-bundle-endpoint"),
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
			mask:       &types.FederationRelationshipMask{BundleEndpointProfile: true},
			expErrMsg:  "unable to fetch federation relationship: record not found",
			expErrCode: codes.NotFound,
		},
		{
			name:       "updating a nil federation relationship fails nicely ",
			expErrMsg:  "federation relationship is required",
			expErrCode: codes.InvalidArgument,
		},
		{
			name:       "updating a federation relationship without trust domain fails nicely ",
			expErrMsg:  "trust domain is required",
			expErrCode: codes.InvalidArgument,
			fr: &datastore.FederationRelationship{
				BundleEndpointProfile: datastore.BundleEndpointWeb, // TODO(tjons): if we add unknown values to the enum, we could remove this
			},
		},
		{
			name:       "updating a federation relationship without bundle endpoint URL fails nicely",
			expErrMsg:  "bundle endpoint URL is required",
			expErrCode: codes.InvalidArgument,
			mask:       protoutil.AllTrueFederationRelationshipMask,
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td.org/federated-server"),
			},
		},
		{
			name:       "updating a federation relationship of unknown type fails nicely",
			expErrMsg:  "unknown bundle endpoint profile type: \"wrong-type\"", // TODO(tjons): this doesn't work the same way between SQL and Cassandra
			expErrCode: codes.InvalidArgument,
			mask:       protoutil.AllTrueFederationRelationshipMask,
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
			if tt.expErrMsg != "" {
				s.RequireGRPCStatus(err, tt.expErrCode, wrapErrMsg(tt.expErrMsg))
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

// TODO(tjons): document and justify the removal of this SQL-specific test from the shared test harness.

// func (s *PluginSuite) TestMigration() {
// 	for schemaVersion := range latestSchemaVersion {
// 		s.T().Run(fmt.Sprintf("migration_from_schema_version_%d", schemaVersion), func(t *testing.T) {
// 			require := require.New(t)
// 			dbName := fmt.Sprintf("v%d.sqlite3", schemaVersion)
// 			dbPath := filepath.ToSlash(filepath.Join(s.dir, "migration-"+dbName))
// 			if runtime.GOOS == "windows" {
// 				dbPath = "/" + dbPath
// 			}
// 			dbURI := fmt.Sprintf("file://%s", dbPath)

// 			minimalDB := func() string {
// 				previousMinor := codeVersion
// 				if codeVersion.Minor == 0 {
// 					previousMinor.Major--
// 				} else {
// 					previousMinor.Minor--
// 				}
// 				return fmt.Sprintf(`
// 					CREATE TABLE "migrations" ("id" integer primary key autoincrement, "version" integer,"code_version" varchar(255) );
// 					INSERT INTO migrations("version", "code_version") VALUES (%d,%q);
// 				`, schemaVersion, previousMinor)
// 			}

// 			prepareDB := func(migrationSupported bool) {
// 				dump := migrationDumps[schemaVersion]
// 				if migrationSupported {
// 					require.NotEmpty(dump, "no migration dump set up for schema version")
// 				} else {
// 					require.Empty(dump, "migration dump exists for unsupported schema version")
// 					dump = minimalDB()
// 				}
// 				dumpDB(t, dbPath, dump)
// 				err := s.ds.Configure(ctx, fmt.Sprintf(`
// 					database_type = "sqlite3"
// 					connection_string = %q
// 				`, dbURI))
// 				if migrationSupported {
// 					require.NoError(err)
// 				} else {
// 					require.EqualError(err, fmt.Sprintf("datastore-sql: migrating from schema version %d requires a previous SPIRE release; please follow the upgrade strategy at doc/upgrading.md", schemaVersion))
// 				}
// 			}
// 			switch schemaVersion {
// 			// All of these schema versions were migrated by previous versions
// 			// of SPIRE server and no longer have migration code.
// 			case 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22:
// 				prepareDB(false)
// 			default:
// 				t.Fatalf("no migration test added for schema version %d", schemaVersion)
// 			}
// 		})
// 	}
// }

// TODO(tjons): document and justify the removal of this SQL-specific test from the shared test harness.
//
// We will need something like this for cassandra.
//
// func (s *PluginSuite) TestPristineDatabaseMigrationValues() {
// 	var m Migration
// 	s.Require().NoError(s.ds.db.First(&m).Error)
// 	s.Equal(latestSchemaVersion, m.Version)
// 	s.Equal(codeVersion.String(), m.CodeVersion)
// }

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

// TODO(tjons): document and justify the removal of this SQL-specific test from the shared test harness.
// func (s *PluginSuite) TestBindVar() {
// 	fn := func(n int) string {
// 		return fmt.Sprintf("$%d", n)
// 	}
// 	bound := bindVarsFn(fn, "SELECT whatever FROM foo WHERE x = ? AND y = ?")
// 	s.Require().Equal("SELECT whatever FROM foo WHERE x = $1 AND y = $2", bound)
// }

func (s *PluginSuite) TestSetCAJournal() {
	testCases := []struct {
		name      string
		code      codes.Code
		msg       string
		caJournal *datastore.CAJournal
	}{
		{
			name: "creating a new CA journal succeeds",
			caJournal: &datastore.CAJournal{
				Data:                  []byte("test data"),
				ActiveX509AuthorityID: "x509-authority-id",
			},
		},
		{
			name: "nil CA journal",
			code: codes.InvalidArgument,
			msg:  "ca journal is required",
		},
		{
			name: "try to update a non existing CA journal",
			code: codes.NotFound,
			msg:  _notFoundErrMsg,
			caJournal: &datastore.CAJournal{
				ID:                    999,
				Data:                  []byte("test data"),
				ActiveX509AuthorityID: "x509-authority-id",
			},
		},
	}

	for _, tt := range testCases {
		s.T().Run(tt.name, func(t *testing.T) {
			caJournal, err := s.ds.SetCAJournal(ctx, tt.caJournal)
			spiretest.RequireGRPCStatus(t, err, tt.code, wrapErrMsg(tt.msg))
			if tt.code != codes.OK {
				require.Nil(t, caJournal)
				return
			}

			assertCAJournal(t, tt.caJournal, caJournal)
		})
	}
}

func (s *PluginSuite) TestFetchCAJournal() {
	testCases := []struct {
		name                  string
		activeX509AuthorityID string
		code                  codes.Code
		msg                   string
		caJournal             *datastore.CAJournal
	}{
		{
			name:                  "fetching an existent CA journal",
			activeX509AuthorityID: "x509-authority-id",
			caJournal: func() *datastore.CAJournal {
				caJournal, err := s.ds.SetCAJournal(ctx, &datastore.CAJournal{
					ActiveX509AuthorityID: "x509-authority-id",
					Data:                  []byte("test data"),
				})
				s.Require().NoError(err)
				return caJournal
			}(),
		},
		{
			name:                  "non-existent X509 authority ID returns nil",
			activeX509AuthorityID: "non-existent-x509-authority-id",
		},
		{
			name: "fetching without specifying an active authority ID fails",
			code: codes.InvalidArgument,
			msg:  "active X509 authority ID is required",
		},
	}

	for _, tt := range testCases {
		s.T().Run(tt.name, func(t *testing.T) {
			caJournal, err := s.ds.FetchCAJournal(ctx, tt.activeX509AuthorityID)
			spiretest.RequireGRPCStatus(t, err, tt.code, wrapErrMsg(tt.msg))
			if tt.code != codes.OK {
				require.Nil(t, caJournal)
				return
			}

			assert.Equal(t, tt.caJournal, caJournal)
		})
	}
}

func (s *PluginSuite) TestPruneCAJournal() {
	now := time.Now()
	t := now.Add(time.Hour)
	entries := &journal.Entries{
		X509CAs: []*journal.X509CAEntry{
			{
				NotAfter: t.Add(-time.Hour * 6).Unix(),
			},
		},
		JwtKeys: []*journal.JWTKeyEntry{
			{
				NotAfter: t.Add(time.Hour * 6).Unix(),
			},
		},
	}

	entriesBytes, err := proto.Marshal(entries)
	s.Require().NoError(err)

	// Store CA journal in datastore
	caJournal, err := s.ds.SetCAJournal(ctx, &datastore.CAJournal{
		ActiveX509AuthorityID: "x509-authority-1",
		Data:                  entriesBytes,
	})
	s.Require().NoError(err)

	// Run a PruneCAJournals operation specifying a time that is before the
	// expiration of all the authorities. The CA journal should not be pruned.
	s.Require().NoError(s.ds.PruneCAJournals(ctx, t.Add(-time.Hour*12).Unix()))
	caj, err := s.ds.FetchCAJournal(ctx, "x509-authority-1")
	s.Require().NoError(err)
	s.Require().Equal(caJournal, caj)

	// Run a PruneCAJournals operation specifying a time that is before the
	// expiration of one of the authorities, but not all the authorities.
	// The CA journal should not be pruned.
	s.Require().NoError(s.ds.PruneCAJournals(ctx, t.Unix()))
	caj, err = s.ds.FetchCAJournal(ctx, "x509-authority-1")
	s.Require().NoError(err)
	s.Require().Equal(caJournal, caj)

	// Run a PruneCAJournals operation specifying a time that is after the
	// expiration of all the authorities. The CA journal should be pruned.
	s.Require().NoError(s.ds.PruneCAJournals(ctx, t.Add(time.Hour*12).Unix()))
	caj, err = s.ds.FetchCAJournal(ctx, "x509-authority-1")
	s.Require().NoError(err)
	s.Require().Nil(caj)
}

// TODO(tjons): document and justify the removal of this test case
//
// It's specific to the SQL implementation and thus not relevant for testing
// the DataStore contract.
//
// func (s *PluginSuite) TestBuildQuestionsAndPlaceholders() {
// 	for _, tt := range []struct {
// 		name                 string
// 		entries              []string
// 		expectedQuestions    string
// 		expectedPlaceholders string
// 	}{
// 		{
// 			name:                 "No args",
// 			expectedQuestions:    "",
// 			expectedPlaceholders: "",
// 		},
// 		{
// 			name:                 "One arg",
// 			entries:              []string{"a"},
// 			expectedQuestions:    "?",
// 			expectedPlaceholders: "$1",
// 		},
// 		{
// 			name:                 "Five args",
// 			entries:              []string{"a", "b", "c", "e", "f"},
// 			expectedQuestions:    "?,?,?,?,?",
// 			expectedPlaceholders: "$1,$2,$3,$4,$5",
// 		},
// 	} {
// 		s.T().Run(tt.name, func(t *testing.T) {
// 			questions := buildQuestions(tt.entries)
// 			s.Require().Equal(tt.expectedQuestions, questions)
// 			placeholders := buildPlaceholders(tt.entries)
// 			s.Require().Equal(tt.expectedPlaceholders, placeholders)
// 		})
// 	}
// }

func (s *PluginSuite) getTestDataFromJSON(data []byte, jsonValue any) {
	err := json.Unmarshal(data, &jsonValue)
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

func (s *PluginSuite) getNodeSelectors(spiffeID string) []*common.Selector {
	selectors, err := s.ds.GetNodeSelectors(ctx, spiffeID, datastore.RequireCurrent)
	s.Require().NoError(err)
	return selectors
}

func (s *PluginSuite) listNodeSelectors(req *datastore.ListNodeSelectorsRequest) *datastore.ListNodeSelectorsResponse {
	resp, err := s.ds.ListNodeSelectors(ctx, req)
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	return resp
}

// TODO(tjons): document and justify the removal of this SQL-specific test from the shared harness.
//
//
// func (s *PluginSuite) setNodeSelectors(spiffeID string, selectors []*common.Selector) {
// 	err := s.ds.SetNodeSelectors(ctx, spiffeID, selectors)
// 	s.Require().NoError(err)
// }

// func (s *PluginSuite) TestConfigure() {
// 	tests := []struct {
// 		desc               string
// 		giveDBConfig       string
// 		expectMaxOpenConns int
// 		expectIdle         int
// 	}{
// 		{
// 			desc:               "defaults",
// 			expectMaxOpenConns: 100,
// 			// defined in database/sql
// 			expectIdle: 100,
// 		},
// 		{
// 			desc: "zero values",
// 			giveDBConfig: `
// 			max_open_conns = 0
// 			max_idle_conns = 0
// 			`,
// 			expectMaxOpenConns: 0,
// 			expectIdle:         0,
// 		},
// 		{
// 			desc: "custom values",
// 			giveDBConfig: `
// 			max_open_conns = 1000
// 			max_idle_conns = 50
// 			conn_max_lifetime = "10s"
// 			`,
// 			expectMaxOpenConns: 1000,
// 			expectIdle:         50,
// 		},
// 	}

// 	for _, tt := range tests {
// 		s.T().Run(tt.desc, func(t *testing.T) {
// 			dbPath := filepath.ToSlash(filepath.Join(s.dir, "test-datastore-configure.sqlite3"))

// 			log, _ := test.NewNullLogger()
// 			p := New(log)
// 			err := p.Configure(ctx, fmt.Sprintf(`
// 				database_type = "sqlite3"
// 				log_sql = true
// 				connection_string = "%s"
// 				%s
// 			`, dbPath, tt.giveDBConfig))
// 			require.NoError(t, err)
// 			defer p.Close()

// 			db := p.db.DB.DB()
// 			require.Equal(t, tt.expectMaxOpenConns, db.Stats().MaxOpenConnections)

// 			// begin many queries simultaneously
// 			numQueries := 100
// 			var rowsList []*sql.Rows
// 			for range numQueries {
// 				rows, err := db.Query("SELECT * FROM bundles")
// 				require.NoError(t, err)
// 				rowsList = append(rowsList, rows)
// 			}

// 			// close all open queries, which results in idle connections
// 			for _, rows := range rowsList {
// 				require.NoError(t, rows.Close())
// 			}
// 			require.Equal(t, tt.expectIdle, db.Stats().Idle)
// 		})
// 	}
// }

func (s *PluginSuite) assertEntryEqual(t *testing.T, expectEntry, createdEntry *common.RegistrationEntry, now int64) {
	require.NotEmpty(t, createdEntry.EntryId)
	expectEntry.EntryId = ""
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

func (s *PluginSuite) checkAttestedNodeEvents(expectedEvents []datastore.AttestedNodeEvent, spiffeID string) []datastore.AttestedNodeEvent {
	expectedEvents = append(expectedEvents, datastore.AttestedNodeEvent{
		EventID:  uint(len(expectedEvents) + 1),
		SpiffeID: spiffeID,
	})

	resp, err := s.ds.ListAttestedNodeEvents(ctx, &datastore.ListAttestedNodeEventsRequest{})
	s.Require().NoError(err)
	s.Require().Equal(expectedEvents, resp.Events)

	return expectedEvents
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
func assertSelectorsEqual(t *testing.T, expected, actual map[string][]*common.Selector, msgAndArgs ...any) {
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

func createBundles(t *testing.T, ds datastore.DataStore, trustDomains []string) {
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

func assertCAJournal(t *testing.T, exp, actual *datastore.CAJournal) {
	if exp == nil {
		assert.Nil(t, actual)
		return
	}
	assert.Equal(t, exp.ActiveX509AuthorityID, actual.ActiveX509AuthorityID)
	assert.Equal(t, exp.Data, actual.Data)
}
