package sql

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/datastore"
	testutil "github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

var (
	ctx = context.Background()
)

func TestPlugin(t *testing.T) {
	suite.Run(t, new(PluginSuite))
}

type PluginSuite struct {
	suite.Suite
	dir string

	nextId int
	ds     datastore.Plugin
}

func (s *PluginSuite) SetupSuite() {
	var err error
	s.dir, err = ioutil.TempDir("", "spire-datastore-sql-tests")
	s.Require().NoError(err)
}

func (s *PluginSuite) SetupTest() {
	s.ds = s.newPlugin()
}

func (s *PluginSuite) TearDownSuite() {
	os.RemoveAll(s.dir)
}

func (s *PluginSuite) newPlugin() datastore.Plugin {
	p := New()

	s.nextId++
	dbPath := filepath.Join(s.dir, fmt.Sprintf("db%d.sqlite3", s.nextId))

	_, err := p.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: fmt.Sprintf(`
		database_type = "sqlite3"
		log_sql = true
		connection_string = "file://%s"
		`, dbPath),
	})
	s.Require().NoError(err)

	return p
}

func (s *PluginSuite) TestInvalidPluginConfiguration() {
	_, err := s.ds.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: `
		database_type = "wrong"
		connection_string = "bad"
		`,
	})
	s.Require().EqualError(err, "datastore-sql: unsupported database_type: wrong")
}

func (s *PluginSuite) TestBundleCRUD() {
	cert, _, err := testutil.LoadSVIDFixture()
	s.Require().NoError(err)

	bundle := &datastore.Bundle{
		TrustDomain: "spiffe://foo",
		CaCerts:     cert.Raw,
	}

	// create
	_, err = s.ds.CreateBundle(ctx, &datastore.CreateBundleRequest{
		Bundle: bundle,
	})
	s.Require().NoError(err)

	// fetch
	fresp, err := s.ds.FetchBundle(ctx, &datastore.FetchBundleRequest{TrustDomain: "spiffe://foo"})
	s.Require().NoError(err)
	s.Equal(bundle, fresp.Bundle)

	// list
	lresp, err := s.ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	s.Require().NoError(err)
	s.Equal(1, len(lresp.Bundles))
	s.Equal(bundle, lresp.Bundles[0])

	cert, _, err = testutil.LoadCAFixture()
	s.Require().NoError(err)

	bundle2 := &datastore.Bundle{
		TrustDomain: bundle.TrustDomain,
		CaCerts:     cert.Raw,
	}

	// append
	aresp, err := s.ds.AppendBundle(ctx, &datastore.AppendBundleRequest{
		Bundle: bundle2,
	})
	s.Require().NoError(err)
	certs := append(bundle.CaCerts, cert.Raw...)
	s.Require().NotNil(aresp.Bundle)
	s.Equal(certs, aresp.Bundle.CaCerts)

	// append identical
	aresp, err = s.ds.AppendBundle(ctx, &datastore.AppendBundleRequest{
		Bundle: bundle2,
	})
	s.Require().NoError(err)
	s.Require().NotNil(aresp.Bundle)
	s.Equal(certs, aresp.Bundle.CaCerts)

	// append on a new bundle
	bundle3 := &datastore.Bundle{
		TrustDomain: "spiffe://bar",
		CaCerts:     cert.Raw,
	}
	anresp, err := s.ds.AppendBundle(ctx, &datastore.AppendBundleRequest{
		Bundle: bundle3,
	})
	s.Require().NoError(err)
	s.Equal(bundle3, anresp.Bundle)

	// update
	uresp, err := s.ds.UpdateBundle(ctx, &datastore.UpdateBundleRequest{
		Bundle: bundle2,
	})
	s.Require().NoError(err)
	s.Equal(bundle2, uresp.Bundle)

	lresp, err = s.ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	s.Require().NoError(err)
	s.Equal(2, len(lresp.Bundles))
	s.Equal([]*datastore.Bundle{bundle2, bundle3}, lresp.Bundles)

	// delete
	dresp, err := s.ds.DeleteBundle(ctx, &datastore.DeleteBundleRequest{
		TrustDomain: bundle.TrustDomain,
	})
	s.Require().NoError(err)
	s.Equal(bundle2, dresp.Bundle)

	lresp, err = s.ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	s.Require().NoError(err)
	s.Equal(1, len(lresp.Bundles))
}

func (s *PluginSuite) TestCreateAttestedNodeEntry() {
	entry := &datastore.AttestedNodeEntry{
		SpiffeId:            "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}

	cresp, err := s.ds.CreateAttestedNodeEntry(ctx, &datastore.CreateAttestedNodeEntryRequest{Entry: entry})
	s.Require().NoError(err)
	s.Equal(entry, cresp.Entry)

	fresp, err := s.ds.FetchAttestedNodeEntry(ctx, &datastore.FetchAttestedNodeEntryRequest{SpiffeId: entry.SpiffeId})
	s.Require().NoError(err)
	s.Equal(entry, fresp.Entry)

	sresp, err := s.ds.ListAttestedNodeEntries(ctx, &datastore.ListAttestedNodeEntriesRequest{
		ByExpiresBefore: &wrappers.Int64Value{
			Value: time.Now().Unix(),
		},
	})
	s.Require().NoError(err)
	s.Empty(sresp.Entries)
}

func (s *PluginSuite) TestFetchAttestedNodeEntryMissing() {
	fresp, err := s.ds.FetchAttestedNodeEntry(ctx, &datastore.FetchAttestedNodeEntryRequest{SpiffeId: "missing"})
	s.Require().NoError(err)
	s.Require().Nil(fresp.Entry)
}

func (s *PluginSuite) TestFetchStaleNodeEntries() {
	efuture := &datastore.AttestedNodeEntry{
		SpiffeId:            "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}

	epast := &datastore.AttestedNodeEntry{
		SpiffeId:            "bar",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "deadbeef",
		CertNotAfter:        time.Now().Add(-time.Hour).Unix(),
	}

	_, err := s.ds.CreateAttestedNodeEntry(ctx, &datastore.CreateAttestedNodeEntryRequest{Entry: efuture})
	s.Require().NoError(err)

	_, err = s.ds.CreateAttestedNodeEntry(ctx, &datastore.CreateAttestedNodeEntryRequest{Entry: epast})
	s.Require().NoError(err)

	sresp, err := s.ds.ListAttestedNodeEntries(ctx, &datastore.ListAttestedNodeEntriesRequest{
		ByExpiresBefore: &wrappers.Int64Value{
			Value: time.Now().Unix(),
		},
	})
	s.Require().NoError(err)
	s.Equal([]*datastore.AttestedNodeEntry{epast}, sresp.Entries)
}

func (s *PluginSuite) TestUpdateAttestedNodeEntry() {
	entry := &datastore.AttestedNodeEntry{
		SpiffeId:            "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}

	userial := "deadbeef"
	uexpires := time.Now().Add(time.Hour * 2).Unix()

	_, err := s.ds.CreateAttestedNodeEntry(ctx, &datastore.CreateAttestedNodeEntryRequest{Entry: entry})
	s.Require().NoError(err)

	uresp, err := s.ds.UpdateAttestedNodeEntry(ctx, &datastore.UpdateAttestedNodeEntryRequest{
		SpiffeId:         entry.SpiffeId,
		CertSerialNumber: userial,
		CertNotAfter:     uexpires,
	})
	s.Require().NoError(err)

	uentry := uresp.Entry
	s.Require().NotNil(uentry)

	s.Equal(entry.SpiffeId, uentry.SpiffeId)
	s.Equal(entry.AttestationDataType, uentry.AttestationDataType)
	s.Equal(userial, uentry.CertSerialNumber)
	s.Equal(uexpires, uentry.CertNotAfter)

	fresp, err := s.ds.FetchAttestedNodeEntry(ctx, &datastore.FetchAttestedNodeEntryRequest{SpiffeId: entry.SpiffeId})
	s.Require().NoError(err)

	fentry := fresp.Entry
	s.Require().NotNil(fentry)

	s.Equal(entry.SpiffeId, fentry.SpiffeId)
	s.Equal(entry.AttestationDataType, fentry.AttestationDataType)
	s.Equal(userial, fentry.CertSerialNumber)
	s.Equal(uexpires, fentry.CertNotAfter)
}

func (s *PluginSuite) TestDeleteAttestedNodeEntry() {
	entry := &datastore.AttestedNodeEntry{
		SpiffeId:            "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
	}

	_, err := s.ds.CreateAttestedNodeEntry(ctx, &datastore.CreateAttestedNodeEntryRequest{Entry: entry})
	s.Require().NoError(err)

	dresp, err := s.ds.DeleteAttestedNodeEntry(ctx, &datastore.DeleteAttestedNodeEntryRequest{SpiffeId: entry.SpiffeId})
	s.Require().NoError(err)
	s.Equal(entry, dresp.Entry)

	fresp, err := s.ds.FetchAttestedNodeEntry(ctx, &datastore.FetchAttestedNodeEntryRequest{SpiffeId: entry.SpiffeId})
	s.Require().NoError(err)
	s.Nil(fresp.Entry)
}

func (s *PluginSuite) TestCreateNodeResolverMapEntry() {
	entry := &datastore.NodeResolverMapEntry{
		SpiffeId: "main",
		Selector: &common.Selector{
			Type:  "aws-tag",
			Value: "a",
		},
	}

	cresp, err := s.ds.CreateNodeResolverMapEntry(ctx, &datastore.CreateNodeResolverMapEntryRequest{Entry: entry})
	s.Require().NoError(err)
	s.Equal(entry, cresp.Entry)
}

func (s *PluginSuite) TestCreateNodeResolverMapEntryDuplicate() {
	entries := s.createNodeResolverMapEntries(s.ds)

	entry := entries[0]
	cresp, err := s.ds.CreateNodeResolverMapEntry(ctx, &datastore.CreateNodeResolverMapEntryRequest{Entry: entry})
	s.Error(err)
	s.Require().Nil(cresp)
}

func (s *PluginSuite) TestFetchNodeResolverMapEntry() {
	entry := &datastore.NodeResolverMapEntry{
		SpiffeId: "main",
		Selector: &common.Selector{
			Type:  "aws-tag",
			Value: "a",
		},
	}

	cresp, err := s.ds.CreateNodeResolverMapEntry(ctx, &datastore.CreateNodeResolverMapEntryRequest{Entry: entry})
	s.Require().NoError(err)
	s.Equal(entry, cresp.Entry)
}

func (s *PluginSuite) TestDeleteNodeResolverMapEntry() {
	// remove entries for the specific (spiffe_id,type,value)
	entries := s.createNodeResolverMapEntries(s.ds)

	entry_removed := entries[0]

	dresp, err := s.ds.DeleteNodeResolverMapEntry(ctx, &datastore.DeleteNodeResolverMapEntryRequest{Entry: entry_removed})
	s.Require().NoError(err)

	s.Equal(entries[0:1], dresp.Entries)

	for idx, entry := range entries[1:] {
		fresp, err := s.ds.ListNodeResolverMapEntries(ctx, &datastore.ListNodeResolverMapEntriesRequest{SpiffeId: entry.SpiffeId})
		s.Require().NoError(err, idx)
		s.Require().Len(fresp.Entries, 1, "%v", idx)
		s.Equal(entry, fresp.Entries[0], "%v", idx)
	}
}

func (s *PluginSuite) TestDeleteNodeResolverMapEntryAll() {
	// remove all entries for the spiffe_id
	entries := s.createNodeResolverMapEntries(s.ds)

	entry_removed := &datastore.NodeResolverMapEntry{
		SpiffeId: entries[0].SpiffeId,
	}

	dresp, err := s.ds.DeleteNodeResolverMapEntry(ctx, &datastore.DeleteNodeResolverMapEntryRequest{Entry: entry_removed})
	s.Require().NoError(err)

	s.Equal(entries[0:2], dresp.Entries)

	{
		entry := entry_removed
		fresp, err := s.ds.ListNodeResolverMapEntries(ctx, &datastore.ListNodeResolverMapEntriesRequest{SpiffeId: entry.SpiffeId})
		s.Require().NoError(err)
		s.Empty(fresp.Entries)
	}

	{
		entry := entries[2]
		fresp, err := s.ds.ListNodeResolverMapEntries(ctx, &datastore.ListNodeResolverMapEntriesRequest{SpiffeId: entry.SpiffeId})
		s.Require().NoError(err)
		s.NotEmpty(fresp.Entries)
	}
}

func (s *PluginSuite) createNodeResolverMapEntries(ds datastore.DataStore) []*datastore.NodeResolverMapEntry {
	entries := []*datastore.NodeResolverMapEntry{
		{
			SpiffeId: "main",
			Selector: &common.Selector{
				Type:  "aws-tag",
				Value: "a",
			},
		},
		{
			SpiffeId: "main",
			Selector: &common.Selector{
				Type:  "aws-tag",
				Value: "b",
			},
		},
		{
			SpiffeId: "other",
			Selector: &common.Selector{
				Type:  "aws-tag",
				Value: "a",
			},
		},
	}

	for idx, entry := range entries {
		_, err := ds.CreateNodeResolverMapEntry(ctx, &datastore.CreateNodeResolverMapEntryRequest{Entry: entry})
		s.Require().NoError(err, "%v", idx)
	}

	return entries
}

func (s *PluginSuite) TestCreateRegistrationEntry() {
	var validRegistrationEntries []*common.RegistrationEntry
	s.getTestDataFromJsonFile(filepath.Join("testdata", "valid_registration_entries.json"), &validRegistrationEntries)

	for _, validRegistrationEntry := range validRegistrationEntries {
		createRegistrationEntryResponse, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{Entry: validRegistrationEntry})
		s.Require().NoError(err)
		s.NotNil(createRegistrationEntryResponse)
		s.NotEmpty(createRegistrationEntryResponse.EntryId)
	}
}

func (s *PluginSuite) TestCreateInvalidRegistrationEntry() {
	var invalidRegistrationEntries []*common.RegistrationEntry
	s.getTestDataFromJsonFile(filepath.Join("testdata", "invalid_registration_entries.json"), &invalidRegistrationEntries)

	for _, invalidRegistrationEntry := range invalidRegistrationEntries {
		createRegistrationEntryResponse, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{Entry: invalidRegistrationEntry})
		s.Require().Error(err)
		s.Require().Nil(createRegistrationEntryResponse)
	}

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
	}

	createRegistrationEntryResponse, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{Entry: registeredEntry})
	s.Require().NoError(err)
	s.Require().NotNil(createRegistrationEntryResponse)
	registeredEntry.EntryId = createRegistrationEntryResponse.EntryId

	fetchRegistrationEntryResponse, err := s.ds.FetchRegistrationEntry(ctx, &datastore.FetchRegistrationEntryRequest{EntryId: createRegistrationEntryResponse.EntryId})
	s.Require().NoError(err)
	s.Require().NotNil(fetchRegistrationEntryResponse)
	s.Equal(registeredEntry, fetchRegistrationEntryResponse.Entry)
}

func (s *PluginSuite) TestFetchInexistentRegistrationEntry() {
	fetchRegistrationEntryResponse, err := s.ds.FetchRegistrationEntry(ctx, &datastore.FetchRegistrationEntryRequest{EntryId: "INEXISTENT"})
	s.Require().NoError(err)
	s.Require().Nil(fetchRegistrationEntryResponse.Entry)
}

func (s *PluginSuite) TestFetchRegistrationEntries() {
	entry1 := &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
			{Type: "Type2", Value: "Value2"},
			{Type: "Type3", Value: "Value3"},
		},
		SpiffeId: "spiffe://example.org/foo",
		ParentId: "spiffe://example.org/bar",
		Ttl:      1,
	}

	entry2 := &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type3", Value: "Value3"},
			{Type: "Type4", Value: "Value4"},
			{Type: "Type5", Value: "Value5"},
		},
		SpiffeId: "spiffe://example.org/baz",
		ParentId: "spiffe://example.org/bat",
		Ttl:      2,
	}

	createRegistrationEntryResponse, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{Entry: entry1})
	s.Require().NoError(err)
	s.Require().NotNil(createRegistrationEntryResponse)
	entry1.EntryId = createRegistrationEntryResponse.EntryId

	createRegistrationEntryResponse, err = s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{Entry: entry2})
	s.Require().NoError(err)
	s.Require().NotNil(createRegistrationEntryResponse)
	entry2.EntryId = createRegistrationEntryResponse.EntryId

	listRegistrationEntriesResponse, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	s.Require().NoError(err)
	s.Require().NotNil(listRegistrationEntriesResponse)

	expectedResponse := &datastore.ListRegistrationEntriesResponse{
		Entries: []*common.RegistrationEntry{entry2, entry1},
	}
	s.Equal(expectedResponse, listRegistrationEntriesResponse)
}

func (s *PluginSuite) TestUpdateRegistrationEntry() {
	entry1 := &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
			{Type: "Type2", Value: "Value2"},
			{Type: "Type3", Value: "Value3"},
		},
		SpiffeId: "spiffe://example.org/foo",
		ParentId: "spiffe://example.org/bar",
		Ttl:      1,
	}

	createRegistrationEntryResponse, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{Entry: entry1})
	s.Require().NoError(err)
	s.Require().NotNil(createRegistrationEntryResponse)

	// TODO: Refactor message type to take EntryID directly from the entry - see #449
	entry1.EntryId = createRegistrationEntryResponse.EntryId
	entry1.Ttl = 2
	updReq := &datastore.UpdateRegistrationEntryRequest{
		Entry: entry1,
	}
	updateRegistrationEntryResponse, err := s.ds.UpdateRegistrationEntry(ctx, updReq)
	s.Require().NoError(err)
	s.Require().NotNil(updateRegistrationEntryResponse)

	fetchRegistrationEntryResponse, err := s.ds.FetchRegistrationEntry(ctx, &datastore.FetchRegistrationEntryRequest{EntryId: updReq.Entry.EntryId})
	s.Require().NoError(err)
	s.Require().NotNil(fetchRegistrationEntryResponse)

	expectedResponse := &datastore.FetchRegistrationEntryResponse{Entry: entry1}
	s.Equal(expectedResponse, fetchRegistrationEntryResponse)
}

func (s *PluginSuite) TestDeleteRegistrationEntry() {
	entry1 := &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type1", Value: "Value1"},
			{Type: "Type2", Value: "Value2"},
			{Type: "Type3", Value: "Value3"},
		},
		SpiffeId: "spiffe://example.org/foo",
		ParentId: "spiffe://example.org/bar",
		Ttl:      1,
	}

	entry2 := &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{Type: "Type3", Value: "Value3"},
			{Type: "Type4", Value: "Value4"},
			{Type: "Type5", Value: "Value5"},
		},
		SpiffeId: "spiffe://example.org/baz",
		ParentId: "spiffe://example.org/bat",
		Ttl:      2,
	}

	res1, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{Entry: entry1})
	s.Require().NoError(err)
	s.Require().NotNil(res1)
	entry1.EntryId = res1.EntryId

	res2, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{Entry: entry2})
	s.Require().NoError(err)
	s.Require().NotNil(res2)
	entry2.EntryId = res2.EntryId

	// Make sure we deleted the right one
	delRes, err := s.ds.DeleteRegistrationEntry(ctx, &datastore.DeleteRegistrationEntryRequest{EntryId: res1.EntryId})
	s.Require().NoError(err)
	s.Require().Equal(entry1, delRes.Entry)
}

func (s *PluginSuite) TestListParentIDEntries() {
	allEntries := testutil.GetRegistrationEntries("entries.json")
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
			for _, entry := range test.registrationEntries {
				r, _ := ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{Entry: entry})
				entry.EntryId = r.EntryId
			}
			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				ByParentId: &wrappers.StringValue{
					Value: test.parentID,
				},
			})
			s.Require().NoError(err)
			s.Equal(test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestListSelectorEntries() {
	allEntries := testutil.GetRegistrationEntries("entries.json")
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
			for _, entry := range test.registrationEntries {
				r, err := ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{Entry: entry})
				require.NoError(t, err)
				entry.EntryId = r.EntryId
			}
			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				BySelectors: &datastore.BySelectors{
					Selectors: test.selectors,
				},
			})
			require.NoError(t, err)
			require.Equal(t, test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestListMatchingEntries() {
	allEntries := testutil.GetRegistrationEntries("entries.json")
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
			for _, entry := range test.registrationEntries {
				r, err := ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{Entry: entry})
				s.Require().NoError(err)
				entry.EntryId = r.EntryId
			}
			result, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
				BySelectors: &datastore.BySelectors{
					Selectors:           test.selectors,
					AllowAnyCombination: true,
				},
			})
			s.Require().NoError(err)
			s.Equal(test.expectedList, result.Entries)
		})
	}
}

func (s *PluginSuite) TestCreateJoinToken() {
	now := time.Now().Unix()
	req := &datastore.CreateJoinTokenRequest{
		JoinToken: &datastore.JoinToken{
			Token:  "foobar",
			Expiry: now,
		},
	}
	_, err := s.ds.CreateJoinToken(ctx, req)
	s.Require().NoError(err)

	// Make sure we can't re-register
	_, err = s.ds.CreateJoinToken(ctx, req)
	s.NotNil(err)
}

func (s *PluginSuite) TestCreateAndFetchJoinToken() {
	now := time.Now().Unix()
	joinToken := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: now,
	}
	_, err := s.ds.CreateJoinToken(ctx, &datastore.CreateJoinTokenRequest{
		JoinToken: joinToken,
	})
	s.Require().NoError(err)

	res, err := s.ds.FetchJoinToken(ctx, &datastore.FetchJoinTokenRequest{
		Token: joinToken.Token,
	})
	s.Require().NoError(err)
	s.Equal("foobar", res.JoinToken.Token)
	s.Equal(now, res.JoinToken.Expiry)
}

func (s *PluginSuite) TestDeleteJoinToken() {
	now := time.Now().Unix()
	joinToken1 := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: now,
	}
	_, err := s.ds.CreateJoinToken(ctx, &datastore.CreateJoinTokenRequest{
		JoinToken: joinToken1,
	})
	s.Require().NoError(err)

	joinToken2 := &datastore.JoinToken{
		Token:  "batbaz",
		Expiry: now,
	}
	_, err = s.ds.CreateJoinToken(ctx, &datastore.CreateJoinTokenRequest{
		JoinToken: joinToken2,
	})
	s.Require().NoError(err)

	_, err = s.ds.DeleteJoinToken(ctx, &datastore.DeleteJoinTokenRequest{
		Token: joinToken1.Token,
	})
	s.Require().NoError(err)

	// Should not be able to fetch after delete
	resp, err := s.ds.FetchJoinToken(ctx, &datastore.FetchJoinTokenRequest{
		Token: joinToken1.Token,
	})
	s.Require().NoError(err)
	s.Nil(resp.JoinToken)

	// Second token should still be present
	resp, err = s.ds.FetchJoinToken(ctx, &datastore.FetchJoinTokenRequest{
		Token: joinToken2.Token,
	})
	s.Require().NoError(err)
	s.Equal(joinToken2, resp.JoinToken)
}

func (s *PluginSuite) TestPruneJoinTokens() {
	now := time.Now().Unix()
	joinToken := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: now,
	}
	_, err := s.ds.CreateJoinToken(ctx, &datastore.CreateJoinTokenRequest{
		JoinToken: joinToken,
	})
	s.Require().NoError(err)

	// Ensure we don't prune valid tokens, wind clock back 10s
	_, err = s.ds.PruneJoinTokens(ctx, &datastore.PruneJoinTokensRequest{
		ExpiresBefore: now - 10,
	})
	s.Require().NoError(err)
	resp, err := s.ds.FetchJoinToken(ctx, &datastore.FetchJoinTokenRequest{
		Token: joinToken.Token,
	})
	s.Require().NoError(err)
	s.Equal("foobar", resp.JoinToken.Token)

	// Ensure we prune old tokens
	joinToken.Expiry = (now + 10)
	_, err = s.ds.PruneJoinTokens(ctx, &datastore.PruneJoinTokensRequest{
		ExpiresBefore: now + 10,
	})
	s.Require().NoError(err)
	resp, err = s.ds.FetchJoinToken(ctx, &datastore.FetchJoinTokenRequest{
		Token: joinToken.Token,
	})
	s.Require().NoError(err)
	s.Nil(resp.JoinToken)
}

func (s *PluginSuite) TestGetPluginInfo() {
	resp, err := s.ds.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
}

func (s *PluginSuite) TestMigration() {
	for i := 0; i < codeVersion; i++ {
		dbName := fmt.Sprintf("v%d.sqlite3", i)
		dbPath := filepath.Join(s.dir, "migration-"+dbName)
		// copy the database file from the test data
		s.Require().NoError(copyFile(filepath.Join("testdata", "migration", dbName), dbPath))

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
				Bundle: &datastore.Bundle{
					TrustDomain: "spiffe://otherdomain.org",
				},
			})
			s.Require().NoError(err)
		default:
			s.T().Fatalf("no migration test added for version %d", i)
		}
	}
}

func (s *PluginSuite) TestRace() {
	next := int64(0)
	exp := time.Now().Add(time.Hour).Unix()

	testutil.RaceTest(s.T(), func(t *testing.T) {
		entry := &datastore.AttestedNodeEntry{
			SpiffeId:            fmt.Sprintf("foo%d", atomic.AddInt64(&next, 1)),
			AttestationDataType: "aws-tag",
			CertSerialNumber:    "badcafe",
			CertNotAfter:        exp,
		}

		_, err := s.ds.CreateAttestedNodeEntry(ctx, &datastore.CreateAttestedNodeEntryRequest{Entry: entry})
		require.NoError(t, err)
		_, err = s.ds.FetchAttestedNodeEntry(ctx, &datastore.FetchAttestedNodeEntryRequest{SpiffeId: entry.SpiffeId})
		require.NoError(t, err)
	})
}

func (s *PluginSuite) getTestDataFromJsonFile(filePath string, jsonValue interface{}) {
	invalidRegistrationEntriesJson, err := ioutil.ReadFile(filePath)
	s.Require().NoError(err)

	err = json.Unmarshal(invalidRegistrationEntriesJson, &jsonValue)
	s.Require().NoError(err)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Close()
}
