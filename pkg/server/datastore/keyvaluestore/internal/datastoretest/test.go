package datastoretest

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/protoutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/record"
	"github.com/spiffe/spire/proto/spire/common"
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

	expiredNotAfter        = time.Date(2018, 01, 10, 01, 34, 00, 00, time.UTC)
	validNotAfter          = time.Date(2018, 01, 10, 01, 36, 00, 00, time.UTC)
	betweenExpiredAndValid = time.Date(2018, 01, 10, 01, 35, 00, 00, time.UTC)

	key         = testkey.MustEC256()
	validRoot   *x509.Certificate
	expiredRoot *x509.Certificate
)

func init() {
	selfSign := func(tmpl *x509.Certificate) *x509.Certificate {
		certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if err != nil {
			panic(err)
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			panic(err)
		}
		return cert
	}

	validRoot = selfSign(&x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotAfter:     validNotAfter,
		NotBefore:    validNotAfter.Add(-time.Hour),
	})

	expiredRoot = selfSign(&x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotAfter:     expiredNotAfter,
		NotBefore:    expiredNotAfter.Add(-time.Hour),
	})
}

func Test(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	run := func(name string, test func(*testing.T, func(*testing.T) datastore.DataStore)) {
		t.Run(name, func(t *testing.T) {
			test(t, newDS)
		})
	}

	run("BundleCRUD", testBundleCRUD)
	run("ListBundlesWithPagination", testListBundlesWithPagination)
	run("CountBundles", testCountBundles)
	run("CountAttestedNodes", testCountAttestedNodes)
	run("CountRegistrationEntries", testCountRegistrationEntries)
	run("SetBundle", testSetBundle)
	run("BundlePrune", testBundlePrune)
	run("CreateAttestedNode", testCreateAttestedNode)
	run("FetchAttestedNodeMissing", testFetchAttestedNodeMissing)
	run("ListAttestedNodes", testListAttestedNodes)
	run("UpdateAttestedNode", testUpdateAttestedNode)
	run("DeleteAttestedNode", testDeleteAttestedNode)
	run("NodeSelectors", testNodeSelectors)
	run("ListNodeSelectors", testListNodeSelectors)
	run("SetNodeSelectorsUnderLoad", testSetNodeSelectorsUnderLoad)
	run("CreateRegistrationEntry", testCreateRegistrationEntry)
	run("CreateInvalidRegistrationEntry", testCreateInvalidRegistrationEntry)
	run("FetchRegistrationEntry", testFetchRegistrationEntry)
	run("PruneRegistrationEntries", testPruneRegistrationEntries)
	run("FetchInexistentRegistrationEntry", testFetchInexistentRegistrationEntry)
	run("ListRegistrationEntries", testListRegistrationEntries)
	run("UpdateRegistrationEntry", testUpdateRegistrationEntry)
	run("UpdateRegistrationEntryWithStoreSvid", testUpdateRegistrationEntryWithStoreSvid)
	run("UpdateRegistrationEntryWithMask", testUpdateRegistrationEntryWithMask)
	run("DeleteRegistrationEntry", testDeleteRegistrationEntry)
	run("ListParentIDEntries", testListParentIDEntries)
	run("ListSelectorEntries", testListSelectorEntries)
	run("ListEntriesBySelectorSubset", testListEntriesBySelectorSubset)
	run("ListSelectorEntriesSuperset", testListSelectorEntriesSuperset)
	run("ListEntriesBySelectorMatchAny", testListEntriesBySelectorMatchAny)
	run("ListEntriesByFederatesWithExact", testListEntriesByFederatesWithExact)
	run("ListEntriesByFederatesWithSubset", testListEntriesByFederatesWithSubset)
	run("ListEntriesByFederatesWithMatchAny", testListEntriesByFederatesWithMatchAny)
	run("ListEntriesByFederatesWithSuperset", testListEntriesByFederatesWithSuperset)
	run("RegistrationEntriesFederatesWithSuccess", testRegistrationEntriesFederatesWithSuccess)
	run("CreateJoinToken", testCreateJoinToken)
	run("CreateAndFetchJoinToken", testCreateAndFetchJoinToken)
	run("DeleteJoinToken", testDeleteJoinToken)
	run("PruneJoinTokens", testPruneJoinTokens)
	run("DeleteFederationRelationship", testDeleteFederationRelationship)
	run("FetchFederationRelationship", testFetchFederationRelationship)
	run("CreateFederationRelationship", testCreateFederationRelationship)
	run("ListFederationRelationships", testListFederationRelationships)
	run("UpdateFederationRelationship", testUpdateFederationRelationship)
	run("Race", testRace)
}

func testBundleCRUD(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	bundle := bundleutil.BundleProtoFromRootCA("spiffe://foo", validRoot)

	// fetch non-existent
	fb, err := ds.FetchBundle(ctx, "spiffe://foo")
	require.NoError(t, err)
	require.Nil(t, fb)

	// update non-existent
	_, err = ds.UpdateBundle(ctx, bundle, nil)
	spiretest.AssertGRPCStatus(t, err, codes.NotFound, "failed to update bundle: record not found")

	// delete non-existent
	err = ds.DeleteBundle(ctx, "spiffe://foo", datastore.Restrict)
	spiretest.AssertGRPCCode(t, err, codes.NotFound)

	// create
	_, err = ds.CreateBundle(ctx, bundle)
	require.NoError(t, err)

	// create again (constraint violation)
	_, err = ds.CreateBundle(ctx, bundle)
	spiretest.AssertGRPCCode(t, err, codes.AlreadyExists)

	// fetch
	fb, err = ds.FetchBundle(ctx, "spiffe://foo")
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, bundle, fb)

	// list
	lresp, err := ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	require.NoError(t, err)
	assert.Equal(t, 1, len(lresp.Bundles))
	spiretest.AssertProtoEqual(t, bundle, lresp.Bundles[0])

	bundle2 := bundleutil.BundleProtoFromRootCA(bundle.TrustDomainId, expiredRoot)
	appendedBundle := bundleutil.BundleProtoFromRootCAs(bundle.TrustDomainId,
		[]*x509.Certificate{validRoot, expiredRoot})

	// append
	ab, err := ds.AppendBundle(ctx, bundle2)
	require.NoError(t, err)
	require.NotNil(t, ab)
	spiretest.AssertProtoEqual(t, appendedBundle, ab)

	// append identical
	ab, err = ds.AppendBundle(ctx, bundle2)
	require.NoError(t, err)
	require.NotNil(t, ab)
	spiretest.AssertProtoEqual(t, appendedBundle, ab)

	// append on a new bundle
	bundle3 := bundleutil.BundleProtoFromRootCA("spiffe://bar", expiredRoot)
	ab, err = ds.AppendBundle(ctx, bundle3)
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, bundle3, ab)

	// update with mask: RootCas
	updatedBundle, err := ds.UpdateBundle(ctx, bundle, &common.BundleMask{
		RootCas: true,
	})
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, bundle, updatedBundle)

	lresp, err = ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	require.NoError(t, err)
	assertBundlesEqual(t, []*common.Bundle{bundle, bundle3}, lresp.Bundles)

	// update with mask: RefreshHint
	bundle.RefreshHint = 60
	updatedBundle, err = ds.UpdateBundle(ctx, bundle, &common.BundleMask{
		RefreshHint: true,
	})
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, bundle, updatedBundle)

	lresp, err = ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	require.NoError(t, err)
	assertBundlesEqual(t, []*common.Bundle{bundle, bundle3}, lresp.Bundles)

	// update with mask: JwtSingingKeys
	bundle.JwtSigningKeys = []*common.PublicKey{{Kid: "jwt-key-1"}}
	updatedBundle, err = ds.UpdateBundle(ctx, bundle, &common.BundleMask{
		JwtSigningKeys: true,
	})
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, bundle, updatedBundle)

	lresp, err = ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	require.NoError(t, err)
	assertBundlesEqual(t, []*common.Bundle{bundle, bundle3}, lresp.Bundles)

	// update without mask
	updatedBundle, err = ds.UpdateBundle(ctx, bundle2, nil)
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, bundle2, updatedBundle)

	lresp, err = ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	require.NoError(t, err)
	assertBundlesEqual(t, []*common.Bundle{bundle2, bundle3}, lresp.Bundles)

	// delete
	err = ds.DeleteBundle(ctx, bundle.TrustDomainId, datastore.Restrict)
	require.NoError(t, err)

	lresp, err = ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	require.NoError(t, err)
	assert.Equal(t, 1, len(lresp.Bundles))
	spiretest.AssertProtoEqual(t, bundle3, lresp.Bundles[0])
}

func testListBundlesWithPagination(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	bundle1 := bundleutil.BundleProtoFromRootCA("spiffe://aye", validRoot)
	_, err := ds.CreateBundle(ctx, bundle1)
	require.NoError(t, err)

	bundle2 := bundleutil.BundleProtoFromRootCA("spiffe://bee", expiredRoot)
	_, err = ds.CreateBundle(ctx, bundle2)
	require.NoError(t, err)

	bundle3 := bundleutil.BundleProtoFromRootCA("spiffe://cee", validRoot)
	_, err = ds.CreateBundle(ctx, bundle3)
	require.NoError(t, err)

	bundle4 := bundleutil.BundleProtoFromRootCA("spiffe://dee", validRoot)
	_, err = ds.CreateBundle(ctx, bundle4)
	require.NoError(t, err)

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
				Token:    "spiffe://dee",
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
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			resp, err := ds.ListBundles(ctx, &datastore.ListBundlesRequest{
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

func testCountBundles(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	// Count empty bundles
	count, err := ds.CountBundles(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(0), count)

	// Create bundles
	bundle1 := bundleutil.BundleProtoFromRootCA("spiffe://example.org", validRoot)
	_, err = ds.CreateBundle(ctx, bundle1)
	require.NoError(t, err)

	bundle2 := bundleutil.BundleProtoFromRootCA("spiffe://foo", expiredRoot)
	_, err = ds.CreateBundle(ctx, bundle2)
	require.NoError(t, err)

	bundle3 := bundleutil.BundleProtoFromRootCA("spiffe://bar", validRoot)
	_, err = ds.CreateBundle(ctx, bundle3)
	require.NoError(t, err)

	// Count all
	count, err = ds.CountBundles(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(3), count)
}

func testCountAttestedNodes(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	// Count empty attested nodes
	count, err := ds.CountAttestedNodes(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(0), count)

	// Create attested nodes
	node := &common.AttestedNode{
		SpiffeId:            "spiffe://example.org/foo",
		AttestationDataType: "t1",
		CertSerialNumber:    "1234",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}
	_, err = ds.CreateAttestedNode(ctx, node)
	require.NoError(t, err)

	node2 := &common.AttestedNode{
		SpiffeId:            "spiffe://example.org/bar",
		AttestationDataType: "t2",
		CertSerialNumber:    "5678",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}
	_, err = ds.CreateAttestedNode(ctx, node2)
	require.NoError(t, err)

	// Count all
	count, err = ds.CountAttestedNodes(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(2), count)
}

func testCountRegistrationEntries(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	// Count empty registration entries
	count, err := ds.CountRegistrationEntries(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(0), count)

	// Create attested nodes
	entry := &common.RegistrationEntry{
		ParentId:  "spiffe://example.org/agent",
		SpiffeId:  "spiffe://example.org/foo",
		Selectors: []*common.Selector{{Type: "a", Value: "1"}},
	}
	_, err = ds.CreateRegistrationEntry(ctx, entry)
	require.NoError(t, err)

	entry2 := &common.RegistrationEntry{
		ParentId:  "spiffe://example.org/agent",
		SpiffeId:  "spiffe://example.org/bar",
		Selectors: []*common.Selector{{Type: "a", Value: "2"}},
	}
	_, err = ds.CreateRegistrationEntry(ctx, entry2)
	require.NoError(t, err)

	// Count all
	count, err = ds.CountRegistrationEntries(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(2), count)
}

func testSetBundle(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	// create a couple of bundles for tests. the contents don't really matter
	// as long as they are for the same trust domain but have different contents.
	bundle := bundleutil.BundleProtoFromRootCA("spiffe://foo", validRoot)
	bundle2 := bundleutil.BundleProtoFromRootCA("spiffe://foo", expiredRoot)

	// ensure the bundle does not exist (it shouldn't)
	require.Nil(t, fetchBundle(t, ds, "spiffe://foo"))

	// set the bundle and make sure it is created
	_, err := ds.SetBundle(ctx, bundle)
	require.NoError(t, err)
	spiretest.RequireProtoEqual(t, bundle, fetchBundle(t, ds, "spiffe://foo"))

	// set the bundle and make sure it is updated
	_, err = ds.SetBundle(ctx, bundle2)
	require.NoError(t, err)
	spiretest.RequireProtoEqual(t, bundle2, fetchBundle(t, ds, "spiffe://foo"))
}

func testBundlePrune(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	// Setup
	// Create new bundle with two cert (one valid and one expired)
	bundle := bundleutil.BundleProtoFromRootCAs("spiffe://foo", []*x509.Certificate{validRoot, expiredRoot})

	bundle.JwtSigningKeys = []*common.PublicKey{
		{NotAfter: expiredNotAfter.Unix()},
		{NotAfter: validNotAfter.Unix()},
	}

	// Store bundle in datastore
	_, err := ds.CreateBundle(ctx, bundle)
	require.NoError(t, err)

	// Prune
	// prune non existent bundle should not return error, no bundle to prune
	expiration := time.Now()
	changed, err := ds.PruneBundle(ctx, "spiffe://notexistent", expiration)
	assert.NoError(t, err)
	assert.False(t, changed)

	// prune fails if internal prune bundle fails. For instance, if all certs are expired
	expiration = time.Now()
	changed, err = ds.PruneBundle(ctx, bundle.TrustDomainId, expiration)
	spiretest.AssertGRPCStatus(t, err, codes.Unknown, "prune failed: would prune all certificates")
	assert.False(t, changed)

	// prune should remove expired certs
	changed, err = ds.PruneBundle(ctx, bundle.TrustDomainId, betweenExpiredAndValid)
	assert.NoError(t, err)
	assert.True(t, changed)

	// Fetch and verify pruned bundle is the expected
	expectedPrunedBundle := bundleutil.BundleProtoFromRootCAs("spiffe://foo", []*x509.Certificate{validRoot})
	expectedPrunedBundle.JwtSigningKeys = []*common.PublicKey{{NotAfter: validNotAfter.Unix()}}
	fb, err := ds.FetchBundle(ctx, "spiffe://foo")
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, expectedPrunedBundle, fb)
}

func testCreateAttestedNode(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	node := &common.AttestedNode{
		SpiffeId:            "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}

	attestedNode, err := ds.CreateAttestedNode(ctx, node)
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, node, attestedNode)

	attestedNode, err = ds.FetchAttestedNode(ctx, node.SpiffeId)
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, node, attestedNode)
}

func testFetchAttestedNodeMissing(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	attestedNode, err := ds.FetchAttestedNode(ctx, "missing")
	require.NoError(t, err)
	require.Nil(t, attestedNode)
}

func testListAttestedNodes(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	now := time.Now()
	expired := now.Add(-time.Hour)
	unexpired := now.Add(time.Hour)

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
	bannedFalse := false
	bannedTrue := true
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
		byExpiresBefore     time.Time
		byAttestationType   string
		bySelectors         *datastore.BySelectors
		byBanned            *bool
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
				t.Run(name, func(t *testing.T) {
					ds := newDS(t)

					// Create entries for the test. For convenience, map the actual
					// entry ID to the "test" entry ID, so we can easily pinpoint
					// which entries were unexpectedly missing or included in the
					// listing.
					for _, node := range tt.nodes {
						_, err := ds.CreateAttestedNode(ctx, node)
						require.NoError(t, err)
						err = ds.SetNodeSelectors(ctx, node.SpiffeId, node.Selectors)
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

					for i := 0; ; i++ {
						// Don't loop forever if there is a bug
						if i > len(tt.nodes) {
							require.FailNowf(t, "Exhausted paging limit in test", "tokens=%q spiffeids=%q", tokensIn, actualIDsOut)
						}
						if req.Pagination != nil {
							tokensIn = append(tokensIn, req.Pagination.Token)
						}
						resp, err := ds.ListAttestedNodes(ctx, req)
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

func testUpdateAttestedNode(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
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
		updateNode     *common.AttestedNode
		updateNodeMask *common.AttestedNodeMask
		expUpdatedNode *common.AttestedNode
		expErr         error
	}{
		{
			name: "update non-existing attested node",
			updateNode: &common.AttestedNode{
				SpiffeId:         "non-existent-node-id",
				CertSerialNumber: updatedSerial,
				CertNotAfter:     updatedExpires,
			},
			expErr: record.ErrNotFound,
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
		t.Run(tt.name, func(t *testing.T) {
			ds := newDS(t)

			_, err := ds.CreateAttestedNode(ctx, &common.AttestedNode{
				SpiffeId:            nodeID,
				AttestationDataType: attestationType,
				CertSerialNumber:    serial,
				CertNotAfter:        expires,
				NewCertNotAfter:     newExpires,
				NewCertSerialNumber: newSerial,
			})
			require.NoError(t, err)

			// Update attested node
			updatedNode, err := ds.UpdateAttestedNode(ctx, tt.updateNode, tt.updateNodeMask)
			if tt.expErr != nil {
				require.True(t, errors.Is(err, tt.expErr), "expected error %v; got %v", tt.expErr, err)
				require.Nil(t, updatedNode)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, updatedNode)
			spiretest.RequireProtoEqual(t, tt.expUpdatedNode, updatedNode)

			// Check a fresh fetch shows the updated attested node
			attestedNode, err := ds.FetchAttestedNode(ctx, tt.updateNode.SpiffeId)
			require.NoError(t, err)
			require.NotNil(t, attestedNode)
			spiretest.RequireProtoEqual(t, tt.expUpdatedNode, attestedNode)
		})
	}
}

func testDeleteAttestedNode(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	entry := &common.AttestedNode{
		SpiffeId:            "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}

	// delete it before it exists
	err := ds.DeleteAttestedNode(ctx, entry.SpiffeId)
	assert.True(t, errors.Is(err, record.ErrNotFound), "expected not found; got %v", err)

	_, err = ds.CreateAttestedNode(ctx, entry)
	require.NoError(t, err)

	err = ds.DeleteAttestedNode(ctx, entry.SpiffeId)
	require.NoError(t, err)

	attestedNode, err := ds.FetchAttestedNode(ctx, entry.SpiffeId)
	require.NoError(t, err)
	assert.Nil(t, attestedNode)
}

func testNodeSelectors(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

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
	selectors := getNodeSelectors(t, ds, "foo", datastore.TolerateStale)
	require.Empty(t, selectors)
	selectors = getNodeSelectors(t, ds, "foo", datastore.RequireCurrent)
	require.Empty(t, selectors)

	// set selectors on foo and bar
	setNodeSelectors(t, ds, "foo", foo1)
	setNodeSelectors(t, ds, "bar", bar)

	// get foo selectors
	selectors = getNodeSelectors(t, ds, "foo", datastore.TolerateStale)
	spiretest.RequireProtoListEqual(t, foo1, selectors)
	selectors = getNodeSelectors(t, ds, "foo", datastore.RequireCurrent)
	spiretest.RequireProtoListEqual(t, foo1, selectors)

	// replace foo selectors
	setNodeSelectors(t, ds, "foo", foo2)
	selectors = getNodeSelectors(t, ds, "foo", datastore.TolerateStale)
	spiretest.RequireProtoListEqual(t, foo2, selectors)
	selectors = getNodeSelectors(t, ds, "foo", datastore.RequireCurrent)
	spiretest.RequireProtoListEqual(t, foo2, selectors)

	// delete foo selectors
	setNodeSelectors(t, ds, "foo", []*common.Selector{})
	selectors = getNodeSelectors(t, ds, "foo", datastore.TolerateStale)
	require.Empty(t, selectors)
	selectors = getNodeSelectors(t, ds, "foo", datastore.RequireCurrent)
	require.Empty(t, selectors)

	// get bar selectors (make sure they weren't impacted by deleting foo)
	selectors = getNodeSelectors(t, ds, "bar", datastore.TolerateStale)
	spiretest.RequireProtoListEqual(t, bar, selectors)
	// get bar selectors (make sure they weren't impacted by deleting foo)
	selectors = getNodeSelectors(t, ds, "bar", datastore.RequireCurrent)
	spiretest.RequireProtoListEqual(t, bar, selectors)
}

func testListNodeSelectors(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	t.Run("no selectors exist", func(t *testing.T) {
		req := &datastore.ListNodeSelectorsRequest{}
		resp := listNodeSelectors(t, ds, req)
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
		_, err := ds.CreateAttestedNode(ctx, n)
		require.NoError(t, err)

		selectors := []*common.Selector{
			{
				Type:  "foo",
				Value: strconv.Itoa(i),
			},
		}

		setNodeSelectors(t, ds, n.SpiffeId, selectors)
		selectorMap[n.SpiffeId] = selectors
	}

	nonExpiredSelectorsMap := make(map[string][]*common.Selector, numNonExpiredAttNodes)
	for i := 0; i < numNonExpiredAttNodes; i++ {
		spiffeID := nonExpiredAttNodes[i].SpiffeId
		nonExpiredSelectorsMap[spiffeID] = selectorMap[spiffeID]
	}

	t.Run("list all", func(t *testing.T) {
		req := &datastore.ListNodeSelectorsRequest{}
		resp := listNodeSelectors(t, ds, req)
		assertSelectorsEqual(t, selectorMap, resp.Selectors)
	})

	t.Run("list unexpired", func(t *testing.T) {
		req := &datastore.ListNodeSelectorsRequest{
			ValidAt: now,
		}
		resp := listNodeSelectors(t, ds, req)
		assertSelectorsEqual(t, nonExpiredSelectorsMap, resp.Selectors)
	})
}

func testSetNodeSelectorsUnderLoad(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

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
				err := ds.SetNodeSelectors(ctx, id, selectors)
				if err != nil {
					resultCh <- err
				}
			}
			resultCh <- nil
		}()
	}

	for i := 0; i < numWorkers; i++ {
		require.NoError(t, <-resultCh)
	}
}

func testCreateRegistrationEntry(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	var validRegistrationEntries []*common.RegistrationEntry
	getTestDataFromJSONFile(t, filepath.Join("testdata", "valid_registration_entries.json"), &validRegistrationEntries)

	for _, validRegistrationEntry := range validRegistrationEntries {
		registrationEntry, err := ds.CreateRegistrationEntry(ctx, validRegistrationEntry)
		require.NoError(t, err)
		require.NotNil(t, registrationEntry)
		assert.NotEmpty(t, registrationEntry.EntryId)
		registrationEntry.EntryId = ""
		spiretest.RequireProtoEqual(t, registrationEntry, validRegistrationEntry)
	}
}

func testCreateInvalidRegistrationEntry(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	var invalidRegistrationEntries []*common.RegistrationEntry
	getTestDataFromJSONFile(t, filepath.Join("testdata", "invalid_registration_entries.json"), &invalidRegistrationEntries)

	for _, invalidRegistrationEntry := range invalidRegistrationEntries {
		registrationEntry, err := ds.CreateRegistrationEntry(ctx, invalidRegistrationEntry)
		require.Error(t, err)
		require.Nil(t, registrationEntry)
	}

	// TODO: Check that no entries have been created
}

func testFetchRegistrationEntry(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

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
				SpiffeId: "SpiffeId",
				ParentId: "ParentId",
				Ttl:      1,
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
				SpiffeId:  "SpiffeId",
				ParentId:  "ParentId",
				Ttl:       1,
				StoreSvid: true,
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			createdEntry, err := ds.CreateRegistrationEntry(ctx, tt.entry)
			require.NoError(t, err)
			require.NotNil(t, createdEntry)

			fetchRegistrationEntry, err := ds.FetchRegistrationEntry(ctx, createdEntry.EntryId)
			require.NoError(t, err)
			spiretest.RequireProtoEqual(t, createdEntry, fetchRegistrationEntry)
		})
	}
}

func testPruneRegistrationEntries(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	now := time.Now()
	entry := &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
			{Type: "Type2", Value: "Value2"},
			{Type: "Type3", Value: "Value3"},
		},
		SpiffeId:    "SpiffeId",
		ParentId:    "ParentId",
		Ttl:         1,
		EntryExpiry: now.Unix(),
	}

	createdRegistrationEntry, err := ds.CreateRegistrationEntry(ctx, entry)
	require.NoError(t, err)
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
		t.Run(tt.name, func(t *testing.T) {
			err = ds.PruneRegistrationEntries(ctx, tt.time)
			require.NoError(t, err)
			fetchedRegistrationEntry, err = ds.FetchRegistrationEntry(ctx, createdRegistrationEntry.EntryId)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedRegistrationEntry, fetchedRegistrationEntry)

			//			if tt.expectedLastLog.Message == prunedLogMessage {
			//				spiretest.AssertLastLogs(t, s.hook.AllEntries(), []spiretest.LogEntry{tt.expectedLastLog})
			//			} else {
			//				assert.Equal(t, s.hook.LastEntry().Message, tt.expectedLastLog.Message)
			//			}
		})
	}
}

func testFetchInexistentRegistrationEntry(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	fetchedRegistrationEntry, err := ds.FetchRegistrationEntry(ctx, "INEXISTENT")
	require.NoError(t, err)
	require.Nil(t, fetchedRegistrationEntry)
}

func testListRegistrationEntries(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	testListRegistrationEntriesWithConsistency(t, newDS, datastore.RequireCurrent)
	testListRegistrationEntriesWithConsistency(t, newDS, datastore.TolerateStale)

	ds := newDS(t)

	resp, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		Pagination: &datastore.Pagination{
			PageSize: 0,
		},
	})
	spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "cannot paginate with pagesize = 0")
	require.Nil(t, resp)

	resp, err = ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		Pagination: &datastore.Pagination{
			Token:    "invalid int",
			PageSize: 10,
		},
	})
	require.Error(t, err, "could not parse token 'invalid int'")
	require.Nil(t, resp)

	resp, err = ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		BySelectors: &datastore.BySelectors{},
	})
	spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "cannot list by empty selector set")
	require.Nil(t, resp)
}

func testListRegistrationEntriesWithConsistency(t *testing.T, newDS func(t *testing.T) datastore.DataStore, dataConsistency datastore.DataConsistency) {
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

	foobuzAD1 := makeEntry("foo", "buz", "A", "D")
	foobuzAD1.FederatesWith = []string{"spiffe://federated1.test"}
	foobuzCD := makeEntry("foo", "buz", "C", "D")

	bazbarAB1 := makeEntry("baz", "bar", "A", "B")
	bazbarAB1.FederatesWith = []string{"spiffe://federated1.test"}
	bazbarAD12 := makeEntry("baz", "bar", "A", "D")
	bazbarAD12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}
	bazbarCB2 := makeEntry("baz", "bar", "C", "B")
	bazbarCB2.FederatesWith = []string{"spiffe://federated2.test"}
	bazbarCD12 := makeEntry("baz", "bar", "C", "D")
	bazbarCD12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}
	bazbarAE3 := makeEntry("baz", "bar", "A", "E")
	bazbarAE3.FederatesWith = []string{"spiffe://federated3.test"}

	bazbuzAB12 := makeEntry("baz", "buz", "A", "B")
	bazbuzAB12.FederatesWith = []string{"spiffe://federated1.test", "spiffe://federated2.test"}
	bazbuzB := makeEntry("baz", "buz", "B")
	bazbuzCD := makeEntry("baz", "buz", "C", "D")

	zizzazX := makeEntry("ziz", "zaz", "X")

	for _, tt := range []struct {
		test                  string
		entries               []*common.RegistrationEntry
		pageSize              int32
		byParentID            string
		bySpiffeID            string
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
			t.Run(name, func(t *testing.T) {
				ds := newDS(t)

				createBundle(t, ds, "spiffe://federated1.test")
				createBundle(t, ds, "spiffe://federated2.test")
				createBundle(t, ds, "spiffe://federated3.test")

				// Create entries for the test. For convenience, map the actual
				// entry ID to the "test" entry ID, so we can easily pinpoint
				// which entries were unexpectedly missing or included in the
				// listing.
				entryIDMap := map[string]string{}
				for _, entryIn := range tt.entries {
					entryOut := createRegistrationEntry(t, ds, entryIn)
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
				var actualIDsOut [][]string
				req := &datastore.ListRegistrationEntriesRequest{
					Pagination:      pagination,
					ByParentID:      tt.byParentID,
					BySpiffeID:      tt.bySpiffeID,
					BySelectors:     tt.bySelectors,
					ByFederatesWith: tt.byFederatesWith,
				}

				for i := 0; ; i++ {
					// Don't loop forever if there is a bug
					if i > len(tt.entries) {
						require.FailNowf(t, "Exhausted paging limit in test", "tokens=%q spiffeids=%q", tokensIn, actualIDsOut)
					}
					if req.Pagination != nil {
						tokensIn = append(tokensIn, req.Pagination.Token)
					}
					resp, err := ds.ListRegistrationEntries(ctx, req)
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

func testUpdateRegistrationEntry(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	entry := createRegistrationEntry(t, ds, &common.RegistrationEntry{
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

	updatedRegistrationEntry, err := ds.UpdateRegistrationEntry(ctx, entry, nil)
	require.NoError(t, err)
	// Verify output has expected values
	require.Equal(t, int32(2), entry.Ttl)
	require.True(t, entry.Admin)
	require.True(t, entry.Downstream)

	registrationEntry, err := ds.FetchRegistrationEntry(ctx, entry.EntryId)
	require.NoError(t, err)
	require.NotNil(t, registrationEntry)
	spiretest.RequireProtoEqual(t, updatedRegistrationEntry, registrationEntry)

	entry.EntryId = "badid"
	_, err = ds.UpdateRegistrationEntry(ctx, entry, nil)
	assert.True(t, errors.Is(err, record.ErrNotFound), "expected not found; got %v", err)
}

func testUpdateRegistrationEntryWithStoreSvid(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	entry := createRegistrationEntry(t, ds, &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
			{Type: "Type1", Value: "Value2"},
			{Type: "Type1", Value: "Value3"},
		},
		SpiffeId: "spiffe://example.org/foo",
		ParentId: "spiffe://example.org/bar",
		Ttl:      1,
	})

	entry.StoreSvid = true

	updateRegistrationEntry, err := ds.UpdateRegistrationEntry(ctx, entry, nil)
	require.NoError(t, err)
	require.NotNil(t, updateRegistrationEntry)
	// Verify output has expected values
	require.True(t, entry.StoreSvid)

	fetchRegistrationEntry, err := ds.FetchRegistrationEntry(ctx, entry.EntryId)
	require.NoError(t, err)
	spiretest.RequireProtoEqual(t, updateRegistrationEntry, fetchRegistrationEntry)

	// Update with invalid selectors
	entry.Selectors = []*common.Selector{
		{Type: "Type1", Value: "Value1"},
		{Type: "Type1", Value: "Value2"},
		{Type: "Type2", Value: "Value3"},
	}
	resp, err := ds.UpdateRegistrationEntry(ctx, entry, nil)
	require.Nil(t, resp)
	require.EqualError(t, err, "rpc error: code = Unknown desc = datastore-sql: invalid registration entry: selector types must be the same when store SVID is enabled")
}

func testUpdateRegistrationEntryWithMask(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	// There are 9 fields in a registration entry. Of these, 3 have some validation in the SQL
	// layer. In this test, we update each of the 9 fields and make sure update works, and also check
	// with the mask value false to make sure nothing changes. For the 3 fields that have validation
	// we try with good data, bad data, and with or without a mask (so 4 cases each.)

	// Note that most of the input validation is done in the API layer and has more extensive tests there.
	oldEntry := &common.RegistrationEntry{
		ParentId:       "spiffe://example.org/oldParentId",
		SpiffeId:       "spiffe://example.org/oldSpiffeId",
		Ttl:            1000,
		Selectors:      []*common.Selector{{Type: "Type1", Value: "Value1"}},
		FederatesWith:  []string{"spiffe://dom1.org"},
		Admin:          false,
		EntryExpiry:    1000,
		DnsNames:       []string{"dns1"},
		Downstream:     false,
		StoreSvid:      false,
		RevisionNumber: 1,
	}
	newEntry := &common.RegistrationEntry{
		ParentId:       "spiffe://example.org/oldParentId",
		SpiffeId:       "spiffe://example.org/newSpiffeId",
		Ttl:            1000,
		Selectors:      []*common.Selector{{Type: "Type2", Value: "Value2"}},
		FederatesWith:  []string{"spiffe://dom2.org"},
		Admin:          false,
		EntryExpiry:    1000,
		DnsNames:       []string{"dns2"},
		Downstream:     false,
		StoreSvid:      false,
		RevisionNumber: 1,
	}
	badEntry := &common.RegistrationEntry{
		ParentId:       "not a good parent id",
		SpiffeId:       "",
		Ttl:            -1000,
		Selectors:      []*common.Selector{},
		FederatesWith:  []string{"invalid federated bundle"},
		Admin:          false,
		EntryExpiry:    -2000,
		DnsNames:       []string{"this is a bad domain name "},
		Downstream:     false,
		RevisionNumber: 1,
	}
	// Needed for the FederatesWith field to work
	createBundle(t, ds, "spiffe://dom1.org")
	createBundle(t, ds, "spiffe://dom2.org")

	var id string
	for _, testcase := range []struct {
		name   string
		mask   *common.RegistrationEntryMask
		update func(*common.RegistrationEntry)
		result func(*common.RegistrationEntry)
		err    string
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
			err:    "invalid registration entry: missing SPIFFE ID"},
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
			err:    "invalid registration entry: TTL is not set"},
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
			err:    "invalid registration entry: missing selector list"},
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
			err: "invalid registration entry: selector types must be the same when store SVID is enabled",
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
		// This should update all fields
		{name: "Test With Nil Mask",
			mask:   nil,
			update: func(e *common.RegistrationEntry) { proto.Merge(e, oldEntry) },
			result: func(e *common.RegistrationEntry) {}},
	} {
		tt := testcase
		t.Run(tt.name, func(t *testing.T) {
			if id != "" {
				deleteRegistrationEntry(t, ds, id)
			}
			registrationEntry := createRegistrationEntry(t, ds, oldEntry)
			id = registrationEntry.EntryId

			updateEntry := &common.RegistrationEntry{}
			tt.update(updateEntry)
			updateEntry.EntryId = id
			updatedRegistrationEntry, err := ds.UpdateRegistrationEntry(ctx, updateEntry, tt.mask)

			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				return
			}

			require.NoError(t, err)
			expectedResult := proto.Clone(oldEntry).(*common.RegistrationEntry)
			tt.result(expectedResult)
			expectedResult.EntryId = id
			expectedResult.RevisionNumber++
			spiretest.RequireProtoEqual(t, expectedResult, updatedRegistrationEntry)

			// Fetch and check the results match expectations
			registrationEntry, err = ds.FetchRegistrationEntry(ctx, id)
			require.NoError(t, err)
			require.NotNil(t, registrationEntry)

			spiretest.RequireProtoEqual(t, expectedResult, registrationEntry)
		})
	}
}

func testDeleteRegistrationEntry(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	// delete non-existing
	err := ds.DeleteRegistrationEntry(ctx, "badid")
	assert.True(t, errors.Is(err, record.ErrNotFound), "expected not found; got %v", err)

	entry1 := createRegistrationEntry(t, ds, &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
			{Type: "Type2", Value: "Value2"},
			{Type: "Type3", Value: "Value3"},
		},
		SpiffeId: "spiffe://example.org/foo",
		ParentId: "spiffe://example.org/bar",
		Ttl:      1,
	})

	entry2 := createRegistrationEntry(t, ds, &common.RegistrationEntry{
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
	entriesResp, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	require.NoError(t, err)
	require.Len(t, entriesResp.Entries, 2)

	// Delete again must fails with Not Found
	err = ds.DeleteRegistrationEntry(ctx, entry1.EntryId)
	require.NoError(t, err)

	// Make sure we have now only one registration entry
	entriesResp, err = ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	require.NoError(t, err)
	spiretest.RequireProtoListEqual(t, []*common.RegistrationEntry{entry2}, entriesResp.Entries)

	// Delete again must fails with Not Found
	err = ds.DeleteRegistrationEntry(ctx, entry1.EntryId)
	require.True(t, errors.Is(err, record.ErrNotFound), "expected not found; got %v", err)
}

func testListParentIDEntries(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	allEntries := make([]*common.RegistrationEntry, 0)
	getTestDataFromJSONFile(t, filepath.Join("testdata", "entries.json"), &allEntries)
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
		t.Run(test.name, func(t *testing.T) {
			ds := newDS(t)
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
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func testListSelectorEntries(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	allEntries := make([]*common.RegistrationEntry, 0)
	getTestDataFromJSONFile(t, filepath.Join("testdata", "entries.json"), &allEntries)
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
		t.Run(test.name, func(t *testing.T) {
			ds := newDS(t)
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

func testListEntriesBySelectorSubset(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	allEntries := make([]*common.RegistrationEntry, 0)
	getTestDataFromJSONFile(t, filepath.Join("testdata", "entries.json"), &allEntries)
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
		t.Run(test.name, func(t *testing.T) {
			ds := newDS(t)
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
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func testListSelectorEntriesSuperset(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	allEntries := make([]*common.RegistrationEntry, 0)
	getTestDataFromJSONFile(t, filepath.Join("testdata", "entries.json"), &allEntries)
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
		t.Run(test.name, func(t *testing.T) {
			ds := newDS(t)
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
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func testListEntriesBySelectorMatchAny(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	allEntries := make([]*common.RegistrationEntry, 0)
	getTestDataFromJSONFile(t, filepath.Join("testdata", "entries.json"), &allEntries)
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
		t.Run(test.name, func(t *testing.T) {
			ds := newDS(t)
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
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func testListEntriesByFederatesWithExact(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	allEntries := make([]*common.RegistrationEntry, 0)
	getTestDataFromJSONFile(t, filepath.Join("testdata", "entries_federates_with.json"), &allEntries)
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
		t.Run(test.name, func(t *testing.T) {
			ds := newDS(t)
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
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func testListEntriesByFederatesWithSubset(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	allEntries := make([]*common.RegistrationEntry, 0)
	getTestDataFromJSONFile(t, filepath.Join("testdata", "entries_federates_with.json"), &allEntries)
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
		t.Run(test.name, func(t *testing.T) {
			ds := newDS(t)
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
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func testListEntriesByFederatesWithMatchAny(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	allEntries := make([]*common.RegistrationEntry, 0)
	getTestDataFromJSONFile(t, filepath.Join("testdata", "entries_federates_with.json"), &allEntries)
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
		t.Run(test.name, func(t *testing.T) {
			ds := newDS(t)
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
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func testListEntriesByFederatesWithSuperset(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	allEntries := make([]*common.RegistrationEntry, 0)
	getTestDataFromJSONFile(t, filepath.Join("testdata", "entries_federates_with.json"), &allEntries)
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
		t.Run(test.name, func(t *testing.T) {
			ds := newDS(t)
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
			spiretest.RequireProtoListEqual(t, test.expectedList, result.Entries)
		})
	}
}

func testRegistrationEntriesFederatesWithSuccess(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	// create two bundles but only federate with one. having a second bundle
	// has the side effect of asserting that only the code only associates
	// the entry with the exact bundle referenced during creation.
	createBundle(t, ds, "spiffe://otherdomain.org")
	createBundle(t, ds, "spiffe://otherdomain2.org")

	expected := createRegistrationEntry(t, ds, makeFederatedRegistrationEntry())
	// fetch the entry and make sure the federated trust ids come back
	actual := fetchRegistrationEntry(t, ds, expected.EntryId)
	spiretest.RequireProtoEqual(t, expected, actual)
}

func testCreateJoinToken(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	req := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: time.Now().Truncate(time.Second),
	}
	err := ds.CreateJoinToken(ctx, req)
	require.NoError(t, err)

	// Make sure we can't re-register
	err = ds.CreateJoinToken(ctx, req)
	assert.NotNil(t, err)
}

func testCreateAndFetchJoinToken(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	now := time.Now().Truncate(time.Second)
	joinToken := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: now,
	}

	err := ds.CreateJoinToken(ctx, joinToken)
	require.NoError(t, err)

	res, err := ds.FetchJoinToken(ctx, joinToken.Token)
	require.NoError(t, err)
	assert.Equal(t, "foobar", res.Token)
	assert.Equal(t, now, res.Expiry)
}

func testDeleteJoinToken(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	now := time.Now().Truncate(time.Second)
	joinToken1 := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: now,
	}

	err := ds.CreateJoinToken(ctx, joinToken1)
	require.NoError(t, err)

	joinToken2 := &datastore.JoinToken{
		Token:  "batbaz",
		Expiry: now,
	}

	err = ds.CreateJoinToken(ctx, joinToken2)
	require.NoError(t, err)

	err = ds.DeleteJoinToken(ctx, joinToken1.Token)
	require.NoError(t, err)

	// Should not be able to fetch after delete
	resp, err := ds.FetchJoinToken(ctx, joinToken1.Token)
	require.NoError(t, err)
	assert.Nil(t, resp)

	// Second token should still be present
	resp, err = ds.FetchJoinToken(ctx, joinToken2.Token)
	require.NoError(t, err)
	assert.Equal(t, joinToken2, resp)
}

func testPruneJoinTokens(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	now := time.Now().Truncate(time.Second)
	joinToken := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: now,
	}

	err := ds.CreateJoinToken(ctx, joinToken)
	require.NoError(t, err)

	// Ensure we don't prune valid tokens, wind clock back 10s
	err = ds.PruneJoinTokens(ctx, now.Add(-time.Second*10))
	require.NoError(t, err)

	resp, err := ds.FetchJoinToken(ctx, joinToken.Token)
	require.NoError(t, err)
	assert.Equal(t, "foobar", resp.Token)

	// Ensure we don't prune on the exact ExpiresBefore
	err = ds.PruneJoinTokens(ctx, now)
	require.NoError(t, err)

	resp, err = ds.FetchJoinToken(ctx, joinToken.Token)
	require.NoError(t, err)
	require.NotNil(t, resp, "token was unexpectedly pruned")
	assert.Equal(t, "foobar", resp.Token)

	// Ensure we prune old tokens
	err = ds.PruneJoinTokens(ctx, now.Add(time.Second*10))
	require.NoError(t, err)

	resp, err = ds.FetchJoinToken(ctx, joinToken.Token)
	require.NoError(t, err)
	assert.Nil(t, resp)
}

func testDeleteFederationRelationship(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	testCases := []struct {
		name        string
		trustDomain spiffeid.TrustDomain
		expectCode  codes.Code
		setupFn     func()
	}{
		{
			name:        "deleting an existent federation relationship succeeds",
			trustDomain: spiffeid.RequireTrustDomainFromString("federated-td-web.org"),
			setupFn: func() {
				_, err := ds.CreateFederationRelationship(ctx, &datastore.FederationRelationship{
					TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-web.org"),
					BundleEndpointURL:     requireURLFromString(t, "federated-td-web.org/bundleendpoint"),
					BundleEndpointProfile: datastore.BundleEndpointWeb,
				})
				require.NoError(t, err)
			},
		},
		{
			name:        "deleting an unexistent federation relationship returns not found",
			trustDomain: spiffeid.RequireTrustDomainFromString("non-existent-td.org"),
			expectCode:  codes.NotFound,
		},
		{
			name:       "deleting a federation relationship using an empty trust domain fails nicely",
			expectCode: codes.InvalidArgument,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupFn != nil {
				tt.setupFn()
			}

			err := ds.DeleteFederationRelationship(ctx, tt.trustDomain)
			if tt.expectCode != codes.OK {
				require.Equal(t, tt.expectCode, status.Code(err))
				return
			}
			require.NoError(t, err)

			fr, err := ds.FetchFederationRelationship(ctx, tt.trustDomain)
			require.NoError(t, err)
			require.Nil(t, fr)
		})
	}
}

func testFetchFederationRelationship(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

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
				fr, err := ds.CreateFederationRelationship(ctx, &datastore.FederationRelationship{
					TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-web.org"),
					BundleEndpointURL:     requireURLFromString(t, "federated-td-web.org/bundleendpoint"),
					BundleEndpointProfile: datastore.BundleEndpointWeb,
				})
				require.NoError(t, err)
				return fr
			}(),
		},
		{
			name:        "fetching an existent federation relationship succeeds for spiffe profile",
			trustDomain: spiffeid.RequireTrustDomainFromString("federated-td-spiffe.org"),
			expFR: func() *datastore.FederationRelationship {
				trustDomainBundle := createBundle(t, ds, "spiffe://federated-td-spiffe.org")
				fr, err := ds.CreateFederationRelationship(ctx, &datastore.FederationRelationship{
					TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-spiffe.org"),
					BundleEndpointURL:     requireURLFromString(t, "federated-td-spiffe.org/bundleendpoint"),
					BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
					EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://federated-td-spiffe.org/federated-server"),
					TrustDomainBundle:     trustDomainBundle,
				})
				require.NoError(t, err)
				return fr
			}(),
		},
		{
			name:        "fetching an existent federation relationship succeeds for profile without bundle",
			trustDomain: spiffeid.RequireTrustDomainFromString("domain.test"),
			expFR: func() *datastore.FederationRelationship {
				fr, err := ds.CreateFederationRelationship(ctx, &datastore.FederationRelationship{
					TrustDomain:           spiffeid.RequireTrustDomainFromString("domain.test"),
					BundleEndpointURL:     requireURLFromString(t, "https://domain.test/bundleendpoint"),
					BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
					EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://domain.test/federated-server"),
				})
				require.NoError(t, err)
				return fr
			}(),
		},
		{
			name:        "fetching an unexistent federation relationship returns nil",
			trustDomain: spiffeid.RequireTrustDomainFromString("non-existent-td.org"),
		},
		{
			name:   "fetching en empty trust domain fails nicely",
			expErr: "rpc error: code = InvalidArgument desc = trust domain is required",
		},
		//		{
		//			name:        "fetching a federation relationship with corrupted bundle endpoint URL fails nicely",
		//			expErr:      "rpc error: code = Unknown desc = unable to parse URL: parse \"not-valid-endpoint-url%\": invalid URL escape \"%\"",
		//			trustDomain: spiffeid.RequireTrustDomainFromString("corrupted-bundle-endpoint-url.org"),
		//			expFR: func() *datastore.FederationRelationship { // nolint // returns nil on purpose
		//				model := FederatedTrustDomain{
		//					TrustDomain:           "corrupted-bundle-endpoint-url.org",
		//					BundleEndpointURL:     "not-valid-endpoint-url%",
		//					BundleEndpointProfile: string(datastore.BundleEndpointWeb),
		//				}
		//				require.NoError(t, ds.db.Create(&model).Error)
		//				return nil
		//			}(),
		//		},
		//		{
		//			name:        "fetching a federation relationship with corrupted bundle endpoint SPIFFE ID fails nicely",
		//			expErr:      "rpc error: code = Unknown desc = unable to parse bundle endpoint SPIFFE ID: scheme is missing or invalid",
		//			trustDomain: spiffeid.RequireTrustDomainFromString("corrupted-bundle-endpoint-id.org"),
		//			expFR: func() *datastore.FederationRelationship { // nolint // returns nil on purpose
		//				model := FederatedTrustDomain{
		//					TrustDomain:           "corrupted-bundle-endpoint-id.org",
		//					BundleEndpointURL:     "corrupted-bundle-endpoint-id.org/bundleendpoint",
		//					BundleEndpointProfile: string(datastore.BundleEndpointSPIFFE),
		//					EndpointSPIFFEID:      "invalid-id",
		//				}
		//				require.NoError(t, ds.db.Create(&model).Error)
		//				return nil
		//			}(),
		//		},
		//		{
		//			name:        "fetching a federation relationship with corrupted type fails nicely",
		//			expErr:      "rpc error: code = Unknown desc = unknown bundle endpoint profile type: \"other\"",
		//			trustDomain: spiffeid.RequireTrustDomainFromString("corrupted-endpoint-profile.org"),
		//			expFR: func() *datastore.FederationRelationship { // nolint // returns nil on purpose
		//				model := FederatedTrustDomain{
		//					TrustDomain:           "corrupted-endpoint-profile.org",
		//					BundleEndpointURL:     "corrupted-endpoint-profile.org/bundleendpoint",
		//					BundleEndpointProfile: "other",
		//				}
		//				require.NoError(t, ds.db.Create(&model).Error)
		//				return nil
		//			}(),
		//		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			fr, err := ds.FetchFederationRelationship(ctx, tt.trustDomain)
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

func testCreateFederationRelationship(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	createBundle(t, ds, "spiffe://federated-td-spiffe.org")
	createBundle(t, ds, "spiffe://federated-td-spiffe-with-bundle.org")

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
				BundleEndpointURL:     requireURLFromString(t, "federated-td-web.org/bundleendpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
		},
		{
			name: "creating a new federation relationship succeeds for spiffe profile",
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-spiffe.org"),
				BundleEndpointURL:     requireURLFromString(t, "federated-td-spiffe.org/bundleendpoint"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://federated-td-spiffe.org/federated-server"),
			},
		},
		{
			name: "creating a new federation relationship succeeds for web profile and new bundle",
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-web-with-bundle.org"),
				BundleEndpointURL:     requireURLFromString(t, "federated-td-web-with-bundle.org/bundleendpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
				TrustDomainBundle: func() *common.Bundle {
					newBundle := bundleutil.BundleProtoFromRootCA("spiffe://federated-td-web-with-bundle.org", validRoot)
					newBundle.RefreshHint = int64(10) // modify bundle to assert it was updated
					return newBundle
				}(),
			},
		},
		{
			name: "creating a new federation relationship succeeds for spiffe profile and new bundle",
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("federated-td-spiffe-with-bundle.org"),
				BundleEndpointURL:     requireURLFromString(t, "federated-td-spiffe-with-bundle.org/bundleendpoint"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://federated-td-spiffe-with-bundle.org/federated-server"),
				TrustDomainBundle: func() *common.Bundle {
					newBundle := bundleutil.BundleProtoFromRootCA("spiffe://federated-td-spiffe-with-bundle.org", validRoot)
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
				BundleEndpointURL:     requireURLFromString(t, "federated-td-web.org/bundleendpoint"),
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
				BundleEndpointURL:     requireURLFromString(t, "federated-td-spiffe.org/bundleendpoint"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
			},
		},
		{
			name:       "creating a new SPIFFE federation relationship without initial bundle pass",
			expectCode: codes.OK,
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("no-initial-bundle.org"),
				BundleEndpointURL:     requireURLFromString(t, "no-initial-bundle.org/bundleendpoint"),
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
				BundleEndpointURL:     requireURLFromString(t, "no-initial-bundle.org/bundleendpoint"),
				BundleEndpointProfile: "wrong-type",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			fr, err := ds.CreateFederationRelationship(ctx, tt.fr)
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
				bundle, err := ds.FetchBundle(ctx, fr.TrustDomain.IDString())
				require.NoError(t, err)
				spiretest.RequireProtoEqual(t, bundle, fr.TrustDomainBundle)
			}
		})
	}
}

func testListFederationRelationships(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	trustDomainBundle := createBundle(t, ds, "spiffe://example-2.org")

	fr1, err := ds.CreateFederationRelationship(ctx, &datastore.FederationRelationship{
		TrustDomain:           spiffeid.RequireTrustDomainFromString("example-1.org"),
		BundleEndpointURL:     requireURLFromString(t, "https://example-1-web.org/bundleendpoint"),
		BundleEndpointProfile: datastore.BundleEndpointWeb,
	})
	require.NoError(t, err)

	fr2, err := ds.CreateFederationRelationship(ctx, &datastore.FederationRelationship{
		TrustDomain:           spiffeid.RequireTrustDomainFromString("example-2.org"),
		BundleEndpointURL:     requireURLFromString(t, "https://example-2-web.org/bundleendpoint"),
		BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
		EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://example-2.org/test"),
		TrustDomainBundle:     trustDomainBundle,
	})
	require.NoError(t, err)

	fr3, err := ds.CreateFederationRelationship(ctx, &datastore.FederationRelationship{
		TrustDomain:           spiffeid.RequireTrustDomainFromString("example-3.org"),
		BundleEndpointURL:     requireURLFromString(t, "https://example-3-web.org/bundleendpoint"),
		BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
		EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://example-2.org/test"),
	})
	require.NoError(t, err)

	fr4, err := ds.CreateFederationRelationship(ctx, &datastore.FederationRelationship{
		TrustDomain:           spiffeid.RequireTrustDomainFromString("example-4.org"),
		BundleEndpointURL:     requireURLFromString(t, "https://example-4-web.org/bundleendpoint"),
		BundleEndpointProfile: datastore.BundleEndpointWeb,
	})
	require.NoError(t, err)

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
				Token:    "example-4.org",
				PageSize: 5,
			},
		},
		{
			name: "page size is zero",
			pagination: &datastore.Pagination{
				PageSize: 0,
			},
			expectedErr: "rpc error: code = InvalidArgument desc = cannot paginate with pagesize = 0",
		},
		{
			name: "first page",
			pagination: &datastore.Pagination{
				Token:    "",
				PageSize: 2,
			},
			expectedList: []*datastore.FederationRelationship{fr1, fr2},
			expectedPagination: &datastore.Pagination{
				Token:    "example-2.org",
				PageSize: 2,
			},
		},
		{
			name: "second page",
			pagination: &datastore.Pagination{
				Token:    "example-2.org",
				PageSize: 2,
			},
			expectedList: []*datastore.FederationRelationship{fr3, fr4},
			expectedPagination: &datastore.Pagination{
				Token:    "example-4.org",
				PageSize: 2,
			},
		},
		{
			name:         "third page",
			expectedList: []*datastore.FederationRelationship{},
			pagination: &datastore.Pagination{
				Token:    "example-4.org",
				PageSize: 2,
			},
			expectedPagination: &datastore.Pagination{
				Token:    "",
				PageSize: 2,
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			resp, err := ds.ListFederationRelationships(ctx, &datastore.ListFederationRelationshipsRequest{
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

func testUpdateFederationRelationship(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	createBundle(t, ds, "spiffe://td-with-bundle.org")

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
				BundleEndpointURL:     requireURLFromString(t, "td.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
			fr: &datastore.FederationRelationship{
				TrustDomain:       spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointURL: requireURLFromString(t, "td.org/other-bundle-endpoint"),
			},
			mask: &types.FederationRelationshipMask{BundleEndpointUrl: true},
			expFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointURL:     requireURLFromString(t, "td.org/other-bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
		},
		{
			name: "updating bundle endpoint profile with pre-existent bundle and no input bundle succeeds",
			initialFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-with-bundle.org"),
				BundleEndpointURL:     requireURLFromString(t, "td-with-bundle.org/bundle-endpoint"),
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
				BundleEndpointURL:     requireURLFromString(t, "td-with-bundle.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td-with-bundle.org/federated-server"),
				TrustDomainBundle:     bundleutil.BundleProtoFromRootCA("spiffe://td-with-bundle.org", validRoot),
			},
		},
		{
			name: "updating bundle endpoint profile with pre-existent bundle and input bundle succeeds",
			initialFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-with-bundle.org"),
				BundleEndpointURL:     requireURLFromString(t, "td-with-bundle.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-with-bundle.org"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td-with-bundle.org/federated-server"),
				TrustDomainBundle: func() *common.Bundle {
					newBundle := bundleutil.BundleProtoFromRootCA("spiffe://td-with-bundle.org", validRoot)
					newBundle.RefreshHint = int64(10) // modify bundle to assert it was updated
					return newBundle
				}(),
			},
			mask: &types.FederationRelationshipMask{BundleEndpointProfile: true},
			expFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-with-bundle.org"),
				BundleEndpointURL:     requireURLFromString(t, "td-with-bundle.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td-with-bundle.org/federated-server"),
				TrustDomainBundle: func() *common.Bundle {
					newBundle := bundleutil.BundleProtoFromRootCA("spiffe://td-with-bundle.org", validRoot)
					newBundle.RefreshHint = int64(10)
					return newBundle
				}(),
			},
		},
		{
			name: "updating bundle endpoint profile to SPIFFE without pre-existent bundle succeeds",
			initialFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-without-bundle.org"),
				BundleEndpointURL:     requireURLFromString(t, "td-without-bundle.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
			},
			fr: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-without-bundle.org"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td-without-bundle.org/federated-server"),
				TrustDomainBundle:     bundleutil.BundleProtoFromRootCA("spiffe://td-without-bundle.org", validRoot),
			},
			mask: &types.FederationRelationshipMask{BundleEndpointProfile: true},
			expFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td-without-bundle.org"),
				BundleEndpointURL:     requireURLFromString(t, "td-without-bundle.org/bundle-endpoint"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://td-without-bundle.org/federated-server"),
				TrustDomainBundle:     bundleutil.BundleProtoFromRootCA("spiffe://td-without-bundle.org", validRoot),
			},
		},
		{
			name: "updating bundle endpoint profile to without pre-existent bundle and no input bundle pass",
			initialFR: &datastore.FederationRelationship{
				TrustDomain:           spiffeid.RequireTrustDomainFromString("td.org"),
				BundleEndpointURL:     requireURLFromString(t, "td.org/bundle-endpoint"),
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
				BundleEndpointURL:     requireURLFromString(t, "td.org/bundle-endpoint"),
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
			expErr: "rpc error: code = NotFound desc = failed to update federation relationship: record not found",
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
				BundleEndpointURL:     requireURLFromString(t, "td.org/bundle-endpoint"),
				BundleEndpointProfile: "wrong-type",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.initialFR != nil {
				_, err := ds.CreateFederationRelationship(ctx, tt.initialFR)
				require.NoError(t, err)
				defer func() { require.NoError(t, ds.DeleteFederationRelationship(ctx, tt.initialFR.TrustDomain)) }()
			}

			updatedFR, err := ds.UpdateFederationRelationship(ctx, tt.fr, tt.mask)
			if tt.expErr != "" {
				require.EqualError(t, err, tt.expErr)
				require.Nil(t, updatedFR)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, updatedFR)

			switch tt.expFR.BundleEndpointProfile {
			case datastore.BundleEndpointWeb:
			case datastore.BundleEndpointSPIFFE:
				// Assert bundle is updated
				bundle, err := ds.FetchBundle(ctx, tt.expFR.TrustDomain.IDString())
				require.NoError(t, err)
				spiretest.RequireProtoEqual(t, bundle, updatedFR.TrustDomainBundle)

				// Now that bundles were asserted, set them to nil to be able to compare other fields using Require().Equal
				tt.expFR.TrustDomainBundle = nil
				updatedFR.TrustDomainBundle = nil
			default:
				require.FailNowf(t, "unexpected bundle endpoint profile type: %q", string(tt.expFR.BundleEndpointProfile))
			}

			require.Equal(t, tt.expFR, updatedFR)
		})
	}
}

func testRace(t *testing.T, newDS func(t *testing.T) datastore.DataStore) {
	ds := newDS(t)

	next := int64(0)
	exp := time.Now().Add(time.Hour).Unix()

	testutil.RaceTest(t, func(t *testing.T) {
		node := &common.AttestedNode{
			SpiffeId:            fmt.Sprintf("foo%d", atomic.AddInt64(&next, 1)),
			AttestationDataType: "aws-tag",
			CertSerialNumber:    "badcafe",
			CertNotAfter:        exp,
		}

		_, err := ds.CreateAttestedNode(ctx, node)
		require.NoError(t, err)
		_, err = ds.FetchAttestedNode(ctx, node.SpiffeId)
		require.NoError(t, err)
	})
}

func getTestDataFromJSONFile(t *testing.T, filePath string, jsonValue interface{}) {
	entriesJSON, err := os.ReadFile(filePath)
	require.NoError(t, err)

	err = json.Unmarshal(entriesJSON, &jsonValue)
	require.NoError(t, err)
}

func fetchBundle(t *testing.T, ds datastore.DataStore, trustDomainID string) *common.Bundle {
	bundle, err := ds.FetchBundle(ctx, trustDomainID)
	require.NoError(t, err)
	return bundle
}

func createBundle(t *testing.T, ds datastore.DataStore, trustDomainID string) *common.Bundle {
	bundle, err := ds.CreateBundle(ctx, bundleutil.BundleProtoFromRootCA(trustDomainID, validRoot))
	require.NoError(t, err)
	return bundle
}

func createRegistrationEntry(t *testing.T, ds datastore.DataStore, entry *common.RegistrationEntry) *common.RegistrationEntry {
	registrationEntry, err := ds.CreateRegistrationEntry(ctx, entry)
	require.NoError(t, err)
	require.NotNil(t, registrationEntry)
	return registrationEntry
}

func deleteRegistrationEntry(t *testing.T, ds datastore.DataStore, entryID string) {
	err := ds.DeleteRegistrationEntry(ctx, entryID)
	require.NoError(t, err)
}

func fetchRegistrationEntry(t *testing.T, ds datastore.DataStore, entryID string) *common.RegistrationEntry {
	registrationEntry, err := ds.FetchRegistrationEntry(ctx, entryID)
	require.NoError(t, err)
	require.NotNil(t, registrationEntry)
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

func getNodeSelectors(t *testing.T, ds datastore.DataStore, spiffeID string, dataConsistency datastore.DataConsistency) []*common.Selector {
	selectors, err := ds.GetNodeSelectors(ctx, spiffeID, dataConsistency)
	require.NoError(t, err)
	return selectors
}

func listNodeSelectors(t *testing.T, ds datastore.DataStore, req *datastore.ListNodeSelectorsRequest) *datastore.ListNodeSelectorsResponse {
	resp, err := ds.ListNodeSelectors(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	return resp
}

func setNodeSelectors(t *testing.T, ds datastore.DataStore, spiffeID string, selectors []*common.Selector) {
	err := ds.SetNodeSelectors(ctx, spiffeID, selectors)
	require.NoError(t, err)
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
