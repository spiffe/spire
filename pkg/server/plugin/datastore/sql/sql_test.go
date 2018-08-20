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

	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/datastore"
	testutil "github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

var (
	ctx = context.Background()

	// nextInMemoryId is atomically incremented and appended to the database
	// name for in-memory databases. A unique name is required to prevent
	// the in-memory database from being shared.
	//
	// See https://www.sqlite.org/inmemorydb.html for details.
	nextInMemoryId uint64
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
	_, err = s.ds.CreateBundle(ctx, bundle)
	s.Require().NoError(err)

	// fetch
	fresp, err := s.ds.FetchBundle(ctx, &datastore.Bundle{TrustDomain: "spiffe://foo"})
	s.Require().NoError(err)
	s.Equal(bundle, fresp)

	// list
	lresp, err := s.ds.ListBundles(ctx, &common.Empty{})
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
	aresp, err := s.ds.AppendBundle(ctx, bundle2)
	s.Require().NoError(err)
	certs := append(bundle.CaCerts, cert.Raw...)
	s.Equal(certs, aresp.CaCerts)

	// append identical
	aresp, err = s.ds.AppendBundle(ctx, bundle2)
	s.Require().NoError(err)
	s.Equal(certs, aresp.CaCerts)

	// append on a new bundle
	bundle3 := &datastore.Bundle{
		TrustDomain: "spiffe://bar",
		CaCerts:     cert.Raw,
	}
	anresp, err := s.ds.AppendBundle(ctx, bundle3)
	s.Require().NoError(err)
	s.Equal(bundle3, anresp)

	// update
	uresp, err := s.ds.UpdateBundle(ctx, bundle2)
	s.Require().NoError(err)
	s.Equal(bundle2, uresp)

	lresp, err = s.ds.ListBundles(ctx, &common.Empty{})
	s.Require().NoError(err)
	s.Equal(2, len(lresp.Bundles))
	s.Equal([]*datastore.Bundle{bundle2, bundle3}, lresp.Bundles)

	// delete
	dresp, err := s.ds.DeleteBundle(ctx, &datastore.Bundle{
		TrustDomain: bundle.TrustDomain,
	})
	s.Require().NoError(err)
	s.Equal(bundle2, dresp)

	lresp, err = s.ds.ListBundles(ctx, &common.Empty{})
	s.Require().NoError(err)
	s.Equal(1, len(lresp.Bundles))
}

func (s *PluginSuite) TestCreateAttestedNodeEntry() {
	entry := &datastore.AttestedNodeEntry{
		BaseSpiffeId:        "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertExpirationDate:  time.Now().Add(time.Hour).Format(datastore.TimeFormat),
	}

	cresp, err := s.ds.CreateAttestedNodeEntry(ctx, &datastore.CreateAttestedNodeEntryRequest{AttestedNodeEntry: entry})
	s.Require().NoError(err)
	s.Equal(entry, cresp.AttestedNodeEntry)

	fresp, err := s.ds.FetchAttestedNodeEntry(ctx, &datastore.FetchAttestedNodeEntryRequest{BaseSpiffeId: entry.BaseSpiffeId})
	s.Require().NoError(err)
	s.Equal(entry, fresp.AttestedNodeEntry)

	sresp, err := s.ds.FetchStaleNodeEntries(ctx, &datastore.FetchStaleNodeEntriesRequest{})
	s.Require().NoError(err)
	s.Empty(sresp.AttestedNodeEntryList)
}

func (s *PluginSuite) TestFetchAttestedNodeEntryMissing() {
	fresp, err := s.ds.FetchAttestedNodeEntry(ctx, &datastore.FetchAttestedNodeEntryRequest{BaseSpiffeId: "missing"})
	s.Require().NoError(err)
	s.Require().Nil(fresp.AttestedNodeEntry)
}

func (s *PluginSuite) TestFetchStaleNodeEntries() {
	efuture := &datastore.AttestedNodeEntry{
		BaseSpiffeId:        "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertExpirationDate:  time.Now().Add(time.Hour).Format(datastore.TimeFormat),
	}

	epast := &datastore.AttestedNodeEntry{
		BaseSpiffeId:        "bar",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "deadbeef",
		CertExpirationDate:  time.Now().Add(-time.Hour).Format(datastore.TimeFormat),
	}

	_, err := s.ds.CreateAttestedNodeEntry(ctx, &datastore.CreateAttestedNodeEntryRequest{AttestedNodeEntry: efuture})
	s.Require().NoError(err)

	_, err = s.ds.CreateAttestedNodeEntry(ctx, &datastore.CreateAttestedNodeEntryRequest{AttestedNodeEntry: epast})
	s.Require().NoError(err)

	sresp, err := s.ds.FetchStaleNodeEntries(ctx, &datastore.FetchStaleNodeEntriesRequest{})
	s.Require().NoError(err)
	s.Equal([]*datastore.AttestedNodeEntry{epast}, sresp.AttestedNodeEntryList)
}

func (s *PluginSuite) TestUpdateAttestedNodeEntry() {
	entry := &datastore.AttestedNodeEntry{
		BaseSpiffeId:        "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertExpirationDate:  time.Now().Add(time.Hour).Format(datastore.TimeFormat),
	}

	userial := "deadbeef"
	uexpires := time.Now().Add(time.Hour * 2).Format(datastore.TimeFormat)

	_, err := s.ds.CreateAttestedNodeEntry(ctx, &datastore.CreateAttestedNodeEntryRequest{AttestedNodeEntry: entry})
	s.Require().NoError(err)

	uresp, err := s.ds.UpdateAttestedNodeEntry(ctx, &datastore.UpdateAttestedNodeEntryRequest{
		BaseSpiffeId:       entry.BaseSpiffeId,
		CertSerialNumber:   userial,
		CertExpirationDate: uexpires,
	})
	s.Require().NoError(err)

	uentry := uresp.AttestedNodeEntry
	s.Require().NotNil(uentry)

	s.Equal(entry.BaseSpiffeId, uentry.BaseSpiffeId)
	s.Equal(entry.AttestationDataType, uentry.AttestationDataType)
	s.Equal(userial, uentry.CertSerialNumber)
	s.Equal(uexpires, uentry.CertExpirationDate)

	fresp, err := s.ds.FetchAttestedNodeEntry(ctx, &datastore.FetchAttestedNodeEntryRequest{BaseSpiffeId: entry.BaseSpiffeId})
	s.Require().NoError(err)

	fentry := fresp.AttestedNodeEntry
	s.Require().NotNil(fentry)

	s.Equal(entry.BaseSpiffeId, fentry.BaseSpiffeId)
	s.Equal(entry.AttestationDataType, fentry.AttestationDataType)
	s.Equal(userial, fentry.CertSerialNumber)
	s.Equal(uexpires, fentry.CertExpirationDate)
}

func (s *PluginSuite) TestDeleteAttestedNodeEntry() {
	entry := &datastore.AttestedNodeEntry{
		BaseSpiffeId:        "foo",
		AttestationDataType: "aws-tag",
		CertSerialNumber:    "badcafe",
		CertExpirationDate:  time.Now().Add(time.Hour).Format(datastore.TimeFormat),
	}

	_, err := s.ds.CreateAttestedNodeEntry(ctx, &datastore.CreateAttestedNodeEntryRequest{AttestedNodeEntry: entry})
	s.Require().NoError(err)

	dresp, err := s.ds.DeleteAttestedNodeEntry(ctx, &datastore.DeleteAttestedNodeEntryRequest{BaseSpiffeId: entry.BaseSpiffeId})
	s.Require().NoError(err)
	s.Equal(entry, dresp.AttestedNodeEntry)

	fresp, err := s.ds.FetchAttestedNodeEntry(ctx, &datastore.FetchAttestedNodeEntryRequest{BaseSpiffeId: entry.BaseSpiffeId})
	s.Require().NoError(err)
	s.Nil(fresp.AttestedNodeEntry)
}

func (s *PluginSuite) TestCreateNodeResolverMapEntry() {
	entry := &datastore.NodeResolverMapEntry{
		BaseSpiffeId: "main",
		Selector: &common.Selector{
			Type:  "aws-tag",
			Value: "a",
		},
	}

	cresp, err := s.ds.CreateNodeResolverMapEntry(ctx, &datastore.CreateNodeResolverMapEntryRequest{NodeResolverMapEntry: entry})
	s.Require().NoError(err)

	centry := cresp.NodeResolverMapEntry
	s.Equal(entry, centry)
}

func (s *PluginSuite) TestCreateNodeResolverMapEntryDuplicate() {
	entries := s.createNodeResolverMapEntries(s.ds)

	entry := entries[0]
	cresp, err := s.ds.CreateNodeResolverMapEntry(ctx, &datastore.CreateNodeResolverMapEntryRequest{NodeResolverMapEntry: entry})
	s.Error(err)
	s.Require().Nil(cresp)
}

func (s *PluginSuite) TestFetchNodeResolverMapEntry() {
	entry := &datastore.NodeResolverMapEntry{
		BaseSpiffeId: "main",
		Selector: &common.Selector{
			Type:  "aws-tag",
			Value: "a",
		},
	}

	cresp, err := s.ds.CreateNodeResolverMapEntry(ctx, &datastore.CreateNodeResolverMapEntryRequest{NodeResolverMapEntry: entry})
	s.Require().NoError(err)

	centry := cresp.NodeResolverMapEntry
	s.Equal(entry, centry)
}

func (s *PluginSuite) TestDeleteNodeResolverMapEntry() {
	// remove entries for the specific (spiffe_id,type,value)
	entries := s.createNodeResolverMapEntries(s.ds)

	entry_removed := entries[0]

	dresp, err := s.ds.DeleteNodeResolverMapEntry(ctx, &datastore.DeleteNodeResolverMapEntryRequest{NodeResolverMapEntry: entry_removed})
	s.Require().NoError(err)

	s.Equal(entries[0:1], dresp.NodeResolverMapEntryList)

	for idx, entry := range entries[1:] {
		fresp, err := s.ds.FetchNodeResolverMapEntry(ctx, &datastore.FetchNodeResolverMapEntryRequest{BaseSpiffeId: entry.BaseSpiffeId})
		s.Require().NoError(err, idx)
		s.Require().Len(fresp.NodeResolverMapEntryList, 1, "%v", idx)
		s.Equal(entry, fresp.NodeResolverMapEntryList[0], "%v", idx)
	}
}

func (s *PluginSuite) TestDeleteNodeResolverMapEntryAll() {
	// remove all entries for the spiffe_id
	entries := s.createNodeResolverMapEntries(s.ds)

	entry_removed := &datastore.NodeResolverMapEntry{
		BaseSpiffeId: entries[0].BaseSpiffeId,
	}

	dresp, err := s.ds.DeleteNodeResolverMapEntry(ctx, &datastore.DeleteNodeResolverMapEntryRequest{NodeResolverMapEntry: entry_removed})
	s.Require().NoError(err)

	s.Equal(entries[0:2], dresp.NodeResolverMapEntryList)

	{
		entry := entry_removed
		fresp, err := s.ds.FetchNodeResolverMapEntry(ctx, &datastore.FetchNodeResolverMapEntryRequest{BaseSpiffeId: entry.BaseSpiffeId})
		s.Require().NoError(err)
		s.Empty(fresp.NodeResolverMapEntryList)
	}

	{
		entry := entries[2]
		fresp, err := s.ds.FetchNodeResolverMapEntry(ctx, &datastore.FetchNodeResolverMapEntryRequest{BaseSpiffeId: entry.BaseSpiffeId})
		s.Require().NoError(err)
		s.NotEmpty(fresp.NodeResolverMapEntryList)
	}
}

func (s *PluginSuite) createNodeResolverMapEntries(ds datastore.DataStore) []*datastore.NodeResolverMapEntry {
	entries := []*datastore.NodeResolverMapEntry{
		{
			BaseSpiffeId: "main",
			Selector: &common.Selector{
				Type:  "aws-tag",
				Value: "a",
			},
		},
		{
			BaseSpiffeId: "main",
			Selector: &common.Selector{
				Type:  "aws-tag",
				Value: "b",
			},
		},
		{
			BaseSpiffeId: "other",
			Selector: &common.Selector{
				Type:  "aws-tag",
				Value: "a",
			},
		},
	}

	for idx, entry := range entries {
		_, err := ds.CreateNodeResolverMapEntry(ctx, &datastore.CreateNodeResolverMapEntryRequest{NodeResolverMapEntry: entry})
		s.Require().NoError(err, "%v", idx)
	}

	return entries
}

func (s *PluginSuite) TestCreateRegistrationEntry() {
	var validRegistrationEntries []*common.RegistrationEntry
	s.getTestDataFromJsonFile(filepath.Join("testdata", "valid_registration_entries.json"), &validRegistrationEntries)

	for _, validRegistrationEntry := range validRegistrationEntries {
		createRegistrationEntryResponse, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{RegisteredEntry: validRegistrationEntry})
		s.Require().NoError(err)
		s.NotNil(createRegistrationEntryResponse)
		s.NotEmpty(createRegistrationEntryResponse.RegisteredEntryId)
	}
}

func (s *PluginSuite) TestCreateInvalidRegistrationEntry() {
	var invalidRegistrationEntries []*common.RegistrationEntry
	s.getTestDataFromJsonFile(filepath.Join("testdata", "invalid_registration_entries.json"), &invalidRegistrationEntries)

	for _, invalidRegisteredEntry := range invalidRegistrationEntries {
		createRegistrationEntryResponse, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{RegisteredEntry: invalidRegisteredEntry})
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

	createRegistrationEntryResponse, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{RegisteredEntry: registeredEntry})
	s.Require().NoError(err)
	s.Require().NotNil(createRegistrationEntryResponse)
	registeredEntry.EntryId = createRegistrationEntryResponse.RegisteredEntryId

	fetchRegistrationEntryResponse, err := s.ds.FetchRegistrationEntry(ctx, &datastore.FetchRegistrationEntryRequest{RegisteredEntryId: createRegistrationEntryResponse.RegisteredEntryId})
	s.Require().NoError(err)
	s.Require().NotNil(fetchRegistrationEntryResponse)
	s.Equal(registeredEntry, fetchRegistrationEntryResponse.RegisteredEntry)
}

func (s *PluginSuite) TestFetchInexistentRegistrationEntry() {
	fetchRegistrationEntryResponse, err := s.ds.FetchRegistrationEntry(ctx, &datastore.FetchRegistrationEntryRequest{RegisteredEntryId: "INEXISTENT"})
	s.Require().NoError(err)
	s.Require().Nil(fetchRegistrationEntryResponse.RegisteredEntry)
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

	createRegistrationEntryResponse, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{RegisteredEntry: entry1})
	s.Require().NoError(err)
	s.Require().NotNil(createRegistrationEntryResponse)
	entry1.EntryId = createRegistrationEntryResponse.RegisteredEntryId

	createRegistrationEntryResponse, err = s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{RegisteredEntry: entry2})
	s.Require().NoError(err)
	s.Require().NotNil(createRegistrationEntryResponse)
	entry2.EntryId = createRegistrationEntryResponse.RegisteredEntryId

	fetchRegistrationEntriesResponse, err := s.ds.FetchRegistrationEntries(ctx, &common.Empty{})
	s.Require().NoError(err)
	s.Require().NotNil(fetchRegistrationEntriesResponse)

	expectedResponse := &datastore.FetchRegistrationEntriesResponse{
		RegisteredEntries: &common.RegistrationEntries{
			Entries: []*common.RegistrationEntry{entry2, entry1},
		},
	}
	s.Equal(expectedResponse, fetchRegistrationEntriesResponse)
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

	createRegistrationEntryResponse, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{RegisteredEntry: entry1})
	s.Require().NoError(err)
	s.Require().NotNil(createRegistrationEntryResponse)

	// TODO: Refactor message type to take EntryID directly from the entry - see #449
	entry1.Ttl = 2
	updReq := &datastore.UpdateRegistrationEntryRequest{
		RegisteredEntryId: createRegistrationEntryResponse.RegisteredEntryId,
		RegisteredEntry:   entry1,
	}
	updateRegistrationEntryResponse, err := s.ds.UpdateRegistrationEntry(ctx, updReq)
	s.Require().NoError(err)
	s.Require().NotNil(updateRegistrationEntryResponse)

	fetchRegistrationEntryResponse, err := s.ds.FetchRegistrationEntry(ctx, &datastore.FetchRegistrationEntryRequest{RegisteredEntryId: updReq.RegisteredEntryId})
	s.Require().NoError(err)
	s.Require().NotNil(fetchRegistrationEntryResponse)

	expectedResponse := &datastore.FetchRegistrationEntryResponse{RegisteredEntry: entry1}
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

	res1, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{RegisteredEntry: entry1})
	s.Require().NoError(err)
	s.Require().NotNil(res1)
	entry1.EntryId = res1.RegisteredEntryId

	res2, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{RegisteredEntry: entry2})
	s.Require().NoError(err)
	s.Require().NotNil(res2)
	entry2.EntryId = res2.RegisteredEntryId

	// Make sure we deleted the right one
	delRes, err := s.ds.DeleteRegistrationEntry(ctx, &datastore.DeleteRegistrationEntryRequest{RegisteredEntryId: res1.RegisteredEntryId})
	s.Require().NoError(err)
	s.Require().Equal(entry1, delRes.RegisteredEntry)
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
				r, _ := ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{RegisteredEntry: entry})
				entry.EntryId = r.RegisteredEntryId
			}
			result, err := ds.ListParentIDEntries(ctx, &datastore.ListParentIDEntriesRequest{
				ParentId: test.parentID})
			s.Require().NoError(err)
			s.Equal(test.expectedList, result.RegisteredEntryList)
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
				r, err := ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{RegisteredEntry: entry})
				s.Require().NoError(err)
				entry.EntryId = r.RegisteredEntryId
			}
			result, err := ds.ListSelectorEntries(ctx, &datastore.ListSelectorEntriesRequest{
				Selectors: test.selectors})
			s.Require().NoError(err)
			s.Equal(test.expectedList, result.RegisteredEntryList)
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
				r, err := ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{RegisteredEntry: entry})
				s.Require().NoError(err)
				entry.EntryId = r.RegisteredEntryId
			}
			result, err := ds.ListMatchingEntries(ctx, &datastore.ListSelectorEntriesRequest{
				Selectors: test.selectors})
			s.Require().NoError(err)
			s.Equal(test.expectedList, result.RegisteredEntryList)
		})
	}
}

func (s *PluginSuite) TestRegisterToken() {
	now := time.Now().Unix()
	req := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: now,
	}
	_, err := s.ds.RegisterToken(ctx, req)
	s.Require().NoError(err)

	// Make sure we can't re-register
	_, err = s.ds.RegisterToken(ctx, req)
	s.NotNil(err)
}

func (s *PluginSuite) TestRegisterAndFetchToken() {
	now := time.Now().Unix()
	req := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: now,
	}
	_, err := s.ds.RegisterToken(ctx, req)
	s.Require().NoError(err)

	// Don't need expiry for fetch
	req.Expiry = 0
	res, err := s.ds.FetchToken(ctx, req)
	s.Require().NoError(err)
	s.Equal("foobar", res.Token)
	s.Equal(now, res.Expiry)
}

func (s *PluginSuite) TestDeleteToken() {
	now := time.Now().Unix()
	req1 := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: now,
	}
	_, err := s.ds.RegisterToken(ctx, req1)
	s.Require().NoError(err)

	req2 := &datastore.JoinToken{
		Token:  "batbaz",
		Expiry: now,
	}
	_, err = s.ds.RegisterToken(ctx, req2)
	s.Require().NoError(err)

	// Don't need expiry for delete
	req1.Expiry = 0
	_, err = s.ds.DeleteToken(ctx, req1)
	s.Require().NoError(err)

	// Should not be able to fetch after delete
	resp, err := s.ds.FetchToken(ctx, req1)
	s.Require().NoError(err)
	s.Equal("", resp.Token)

	// Second token should still be present
	resp, err = s.ds.FetchToken(ctx, req2)
	s.Require().NoError(err)
	s.Equal(req2.Token, resp.Token)
}

func (s *PluginSuite) TestPruneTokens() {
	now := time.Now().Unix()
	req := &datastore.JoinToken{
		Token:  "foobar",
		Expiry: now,
	}
	_, err := s.ds.RegisterToken(ctx, req)
	s.Require().NoError(err)

	// Ensure we don't prune valid tokens, wind clock back 10s
	req.Expiry = (now - 10)
	_, err = s.ds.PruneTokens(ctx, req)
	s.Require().NoError(err)
	resp, err := s.ds.FetchToken(ctx, req)
	s.Require().NoError(err)
	s.Equal("foobar", resp.Token)

	// Ensure we prune old tokens
	req.Expiry = (now + 10)
	_, err = s.ds.PruneTokens(ctx, req)
	s.Require().NoError(err)
	resp, err = s.ds.FetchToken(ctx, req)
	s.Require().NoError(err)
	s.Equal("", resp.Token)
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
			_, err := s.ds.CreateBundle(context.Background(), &datastore.Bundle{
				TrustDomain: "spiffe://otherdomain.org",
			})
			s.Require().NoError(err)
		default:
			s.T().Fatalf("no migration test added for version %d", i)
		}
	}
}

func (s *PluginSuite) TestRace() {
	next := int64(0)
	exp := time.Now().Add(time.Hour).Format(datastore.TimeFormat)

	testutil.RaceTest(s.T(), func(t *testing.T) {
		entry := &datastore.AttestedNodeEntry{
			BaseSpiffeId:        fmt.Sprintf("foo%d", atomic.AddInt64(&next, 1)),
			AttestationDataType: "aws-tag",
			CertSerialNumber:    "badcafe",
			CertExpirationDate:  exp,
		}

		_, err := s.ds.CreateAttestedNodeEntry(ctx, &datastore.CreateAttestedNodeEntryRequest{AttestedNodeEntry: entry})
		require.NoError(t, err)
		_, err = s.ds.FetchAttestedNodeEntry(ctx, &datastore.FetchAttestedNodeEntryRequest{BaseSpiffeId: entry.BaseSpiffeId})
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
