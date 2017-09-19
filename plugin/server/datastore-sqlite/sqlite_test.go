package main

import (
	"io/ioutil"
	"testing"
	"time"

	"encoding/json"

	"github.com/spiffe/spire/pkg/common"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/pkg/common/testutil"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type selectors []*common.Selector
type regEntries []*common.RegistrationEntry

func TestFederatedEntry_CRUD(t *testing.T) {
	ds := createDefault(t)

	bundle := &datastore.FederatedBundle{
		FederatedBundleSpiffeId: "foo",
		FederatedTrustBundle:    []byte("bar"),
		Ttl:                     10,
	}

	// create
	_, err := ds.CreateFederatedEntry(&datastore.CreateFederatedEntryRequest{bundle})
	require.NoError(t, err)

	// list
	lresp, err := ds.ListFederatedEntry(&datastore.ListFederatedEntryRequest{})
	require.NoError(t, err)
	assert.Equal(t, []string{bundle.FederatedBundleSpiffeId}, lresp.FederatedBundleSpiffeIdList)

	// update
	bundle2 := &datastore.FederatedBundle{
		FederatedBundleSpiffeId: bundle.FederatedBundleSpiffeId,
		FederatedTrustBundle:    []byte("baz"),
		Ttl:                     20,
	}

	uresp, err := ds.UpdateFederatedEntry(&datastore.UpdateFederatedEntryRequest{bundle2})
	require.NoError(t, err)
	assert.Equal(t, bundle2, uresp.FederatedBundle)

	lresp, err = ds.ListFederatedEntry(&datastore.ListFederatedEntryRequest{})
	require.NoError(t, err)
	assert.Equal(t, []string{bundle.FederatedBundleSpiffeId}, lresp.FederatedBundleSpiffeIdList)

	// delete
	dresp, err := ds.DeleteFederatedEntry(&datastore.DeleteFederatedEntryRequest{
		FederatedBundleSpiffeId: bundle.FederatedBundleSpiffeId,
	})
	require.NoError(t, err)
	assert.Equal(t, bundle2, dresp.FederatedBundle)

	lresp, err = ds.ListFederatedEntry(&datastore.ListFederatedEntryRequest{})
	require.NoError(t, err)
	assert.Len(t, lresp.FederatedBundleSpiffeIdList, 0)
}

func Test_ListFederatedEntry(t *testing.T) {
	ds := createDefault(t)

	lresp, err := ds.ListFederatedEntry(&datastore.ListFederatedEntryRequest{})
	require.NoError(t, err)
	assert.Empty(t, lresp.FederatedBundleSpiffeIdList)
}

func Test_CreateAttestedNodeEntry(t *testing.T) {
	ds := createDefault(t)

	entry := &datastore.AttestedNodeEntry{
		BaseSpiffeId:       "foo",
		AttestedDataType:   "aws-tag",
		CertSerialNumber:   "badcafe",
		CertExpirationDate: time.Now().Add(time.Hour).Format(datastore.TimeFormat),
	}

	cresp, err := ds.CreateAttestedNodeEntry(&datastore.CreateAttestedNodeEntryRequest{entry})
	require.NoError(t, err)
	assert.Equal(t, entry, cresp.AttestedNodeEntry)

	fresp, err := ds.FetchAttestedNodeEntry(&datastore.FetchAttestedNodeEntryRequest{entry.BaseSpiffeId})
	require.NoError(t, err)
	assert.Equal(t, entry, fresp.AttestedNodeEntry)

	sresp, err := ds.FetchStaleNodeEntries(&datastore.FetchStaleNodeEntriesRequest{})
	require.NoError(t, err)
	assert.Empty(t, sresp.AttestedNodeEntryList)
}

func Test_FetchAttestedNodeEntry_missing(t *testing.T) {
	ds := createDefault(t)
	fresp, err := ds.FetchAttestedNodeEntry(&datastore.FetchAttestedNodeEntryRequest{"missing"})
	require.NoError(t, err)
	require.Nil(t, fresp.AttestedNodeEntry)
}

func Test_FetchStaleNodeEntries(t *testing.T) {
	ds := createDefault(t)

	efuture := &datastore.AttestedNodeEntry{
		BaseSpiffeId:       "foo",
		AttestedDataType:   "aws-tag",
		CertSerialNumber:   "badcafe",
		CertExpirationDate: time.Now().Add(time.Hour).Format(datastore.TimeFormat),
	}

	epast := &datastore.AttestedNodeEntry{
		BaseSpiffeId:       "bar",
		AttestedDataType:   "aws-tag",
		CertSerialNumber:   "deadbeef",
		CertExpirationDate: time.Now().Add(-time.Hour).Format(datastore.TimeFormat),
	}

	_, err := ds.CreateAttestedNodeEntry(&datastore.CreateAttestedNodeEntryRequest{efuture})
	require.NoError(t, err)

	_, err = ds.CreateAttestedNodeEntry(&datastore.CreateAttestedNodeEntryRequest{epast})
	require.NoError(t, err)

	sresp, err := ds.FetchStaleNodeEntries(&datastore.FetchStaleNodeEntriesRequest{})
	require.NoError(t, err)
	assert.Equal(t, []*datastore.AttestedNodeEntry{epast}, sresp.AttestedNodeEntryList)
}

func Test_UpdateAttestedNodeEntry(t *testing.T) {
	ds := createDefault(t)

	entry := &datastore.AttestedNodeEntry{
		BaseSpiffeId:       "foo",
		AttestedDataType:   "aws-tag",
		CertSerialNumber:   "badcafe",
		CertExpirationDate: time.Now().Add(time.Hour).Format(datastore.TimeFormat),
	}

	userial := "deadbeef"
	uexpires := time.Now().Add(time.Hour * 2).Format(datastore.TimeFormat)

	_, err := ds.CreateAttestedNodeEntry(&datastore.CreateAttestedNodeEntryRequest{entry})
	require.NoError(t, err)

	uresp, err := ds.UpdateAttestedNodeEntry(&datastore.UpdateAttestedNodeEntryRequest{
		BaseSpiffeId:       entry.BaseSpiffeId,
		CertSerialNumber:   userial,
		CertExpirationDate: uexpires,
	})
	require.NoError(t, err)

	uentry := uresp.AttestedNodeEntry
	require.NotNil(t, uentry)

	assert.Equal(t, entry.BaseSpiffeId, uentry.BaseSpiffeId)
	assert.Equal(t, entry.AttestedDataType, uentry.AttestedDataType)
	assert.Equal(t, userial, uentry.CertSerialNumber)
	assert.Equal(t, uexpires, uentry.CertExpirationDate)

	fresp, err := ds.FetchAttestedNodeEntry(&datastore.FetchAttestedNodeEntryRequest{entry.BaseSpiffeId})
	require.NoError(t, err)

	fentry := fresp.AttestedNodeEntry
	require.NotNil(t, fentry)

	assert.Equal(t, entry.BaseSpiffeId, fentry.BaseSpiffeId)
	assert.Equal(t, entry.AttestedDataType, fentry.AttestedDataType)
	assert.Equal(t, userial, fentry.CertSerialNumber)
	assert.Equal(t, uexpires, fentry.CertExpirationDate)
}

func Test_DeleteAttestedNodeEntry(t *testing.T) {
	ds := createDefault(t)

	entry := &datastore.AttestedNodeEntry{
		BaseSpiffeId:       "foo",
		AttestedDataType:   "aws-tag",
		CertSerialNumber:   "badcafe",
		CertExpirationDate: time.Now().Add(time.Hour).Format(datastore.TimeFormat),
	}

	_, err := ds.CreateAttestedNodeEntry(&datastore.CreateAttestedNodeEntryRequest{entry})
	require.NoError(t, err)

	dresp, err := ds.DeleteAttestedNodeEntry(&datastore.DeleteAttestedNodeEntryRequest{entry.BaseSpiffeId})
	require.NoError(t, err)
	assert.Equal(t, entry, dresp.AttestedNodeEntry)

	fresp, err := ds.FetchAttestedNodeEntry(&datastore.FetchAttestedNodeEntryRequest{entry.BaseSpiffeId})
	require.NoError(t, err)
	assert.Nil(t, fresp.AttestedNodeEntry)
}

func Test_CreateNodeResolverMapEntry(t *testing.T) {
	ds := createDefault(t)

	entry := &datastore.NodeResolverMapEntry{
		BaseSpiffeId: "main",
		Selector: &common.Selector{
			Type:  "aws-tag",
			Value: "a",
		},
	}

	cresp, err := ds.CreateNodeResolverMapEntry(&datastore.CreateNodeResolverMapEntryRequest{entry})
	require.NoError(t, err)

	centry := cresp.NodeResolverMapEntry
	assert.Equal(t, entry, centry)
}

func Test_CreateNodeResolverMapEntry_dupe(t *testing.T) {
	ds := createDefault(t)
	entries := createNodeResolverMapEntries(t, ds)

	entry := entries[0]
	cresp, err := ds.CreateNodeResolverMapEntry(&datastore.CreateNodeResolverMapEntryRequest{entry})
	assert.Error(t, err)
	require.Nil(t, cresp)
}

func Test_FetchNodeResolverMapEntry(t *testing.T) {
	ds := createDefault(t)

	entry := &datastore.NodeResolverMapEntry{
		BaseSpiffeId: "main",
		Selector: &common.Selector{
			Type:  "aws-tag",
			Value: "a",
		},
	}

	cresp, err := ds.CreateNodeResolverMapEntry(&datastore.CreateNodeResolverMapEntryRequest{entry})
	require.NoError(t, err)

	centry := cresp.NodeResolverMapEntry
	assert.Equal(t, entry, centry)
}

func Test_DeleteNodeResolverMapEntry_specific(t *testing.T) {
	// remove entries for the specific (spiffe_id,type,value)

	ds := createDefault(t)
	entries := createNodeResolverMapEntries(t, ds)

	entry_removed := entries[0]

	dresp, err := ds.DeleteNodeResolverMapEntry(&datastore.DeleteNodeResolverMapEntryRequest{entry_removed})
	require.NoError(t, err)

	assert.Equal(t, entries[0:1], dresp.NodeResolverMapEntryList)

	for idx, entry := range entries[1:] {
		fresp, err := ds.FetchNodeResolverMapEntry(&datastore.FetchNodeResolverMapEntryRequest{entry.BaseSpiffeId})
		require.NoError(t, err, idx)
		require.Len(t, fresp.NodeResolverMapEntryList, 1, "%v", idx)
		assert.Equal(t, entry, fresp.NodeResolverMapEntryList[0], "%v", idx)
	}
}

func Test_DeleteNodeResolverMapEntry_all(t *testing.T) {
	// remove all entries for the spiffe_id

	ds := createDefault(t)
	entries := createNodeResolverMapEntries(t, ds)

	entry_removed := &datastore.NodeResolverMapEntry{
		BaseSpiffeId: entries[0].BaseSpiffeId,
	}

	dresp, err := ds.DeleteNodeResolverMapEntry(&datastore.DeleteNodeResolverMapEntryRequest{entry_removed})
	require.NoError(t, err)

	assert.Equal(t, entries[0:2], dresp.NodeResolverMapEntryList)

	{
		entry := entry_removed
		fresp, err := ds.FetchNodeResolverMapEntry(&datastore.FetchNodeResolverMapEntryRequest{entry.BaseSpiffeId})
		require.NoError(t, err)
		assert.Empty(t, fresp.NodeResolverMapEntryList)
	}

	{
		entry := entries[2]
		fresp, err := ds.FetchNodeResolverMapEntry(&datastore.FetchNodeResolverMapEntryRequest{entry.BaseSpiffeId})
		require.NoError(t, err)
		assert.NotEmpty(t, fresp.NodeResolverMapEntryList)
	}
}

func Test_RectifyNodeResolverMapEntries(t *testing.T) {
}

func createNodeResolverMapEntries(t *testing.T, ds datastore.DataStore) []*datastore.NodeResolverMapEntry {
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
		_, err := ds.CreateNodeResolverMapEntry(&datastore.CreateNodeResolverMapEntryRequest{entry})
		require.NoError(t, err, "%v", idx)
	}

	return entries
}

func Test_CreateRegistrationEntry(t *testing.T) {
	ds := createDefault(t)

	var validRegistrationEntries []*common.RegistrationEntry
	err := getTestDataFromJsonFile(t, "_test_data/valid_registration_entries.json", &validRegistrationEntries)
	require.NoError(t, err)

	for _, validRegistrationEntry := range validRegistrationEntries {
		createRegistrationEntryResponse, err := ds.CreateRegistrationEntry(&datastore.CreateRegistrationEntryRequest{validRegistrationEntry})
		require.NoError(t, err)
		assert.NotNil(t, createRegistrationEntryResponse)
		assert.NotEmpty(t, createRegistrationEntryResponse.RegisteredEntryId)
	}
}

func Test_CreateInvalidRegistrationEntry(t *testing.T) {
	ds := createDefault(t)

	var invalidRegistrationEntries []*common.RegistrationEntry
	err := getTestDataFromJsonFile(t, "_test_data/invalid_registration_entries.json", &invalidRegistrationEntries)
	require.NoError(t, err)

	for _, invalidRegisteredEntry := range invalidRegistrationEntries {
		createRegistrationEntryResponse, err := ds.CreateRegistrationEntry(&datastore.CreateRegistrationEntryRequest{invalidRegisteredEntry})
		require.Error(t, err)
		require.Nil(t, createRegistrationEntryResponse)
	}

	// TODO: Check that no entries have been created
}

func Test_FetchRegistrationEntry(t *testing.T) {
	ds := createDefault(t)

	registeredEntry := &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{
				Type:  "Type1",
				Value: "Value1"}, {
				Type:  "Type2",
				Value: "Value2"}, {
				Type:  "Type3",
				Value: "Value3"},
		},
		SpiffeId: "SpiffeId",
		ParentId: "ParentId",
		Ttl:      1,
	}

	createRegistrationEntryResponse, err := ds.CreateRegistrationEntry(&datastore.CreateRegistrationEntryRequest{registeredEntry})
	require.NoError(t, err)
	require.NotNil(t, createRegistrationEntryResponse)

	fetchRegistrationEntryResponse, err := ds.FetchRegistrationEntry(&datastore.FetchRegistrationEntryRequest{createRegistrationEntryResponse.RegisteredEntryId})
	require.NoError(t, err)
	require.NotNil(t, fetchRegistrationEntryResponse)
	assert.Equal(t, registeredEntry, fetchRegistrationEntryResponse.RegisteredEntry)
}

func Test_FetchInexistentRegistrationEntry(t *testing.T) {
	ds := createDefault(t)

	fetchRegistrationEntryResponse, err := ds.FetchRegistrationEntry(&datastore.FetchRegistrationEntryRequest{"INEXISTENT"})
	require.NoError(t, err)
	require.Nil(t, fetchRegistrationEntryResponse.RegisteredEntry)
}

func Test_UpdateRegistrationEntry(t *testing.T) {
	t.Skipf("TODO")
}

func Test_DeleteRegistrationEntry(t *testing.T) {
	t.Skipf("TODO")
}

func TestSqlitePlugin_ListParentIDEntries(t *testing.T) {
	tests := []struct {
		name                 string
		regEntrySameParentID []*common.RegistrationEntry
		parentID             string
		expectedList         []*common.RegistrationEntry
	}{
		{

			name: "test_parentID_found",
			regEntrySameParentID: regEntries{
				&common.RegistrationEntry{
					Selectors: selectors{&common.Selector{Type: "testtype1", Value: "testValue1"},
						&common.Selector{Type: "testtype1", Value: "testValue2"},
						&common.Selector{Type: "testtype1", Value: "testValue3"}},
					ParentId: "spiffe:parent",
					SpiffeId: "spiffe:test1"},
				&common.RegistrationEntry{
					Selectors: selectors{&common.Selector{Type: "testtype1", Value: "testValue1"},
						&common.Selector{Type: "testtype1", Value: "testValue2"},
						&common.Selector{Type: "testtype1", Value: "testValue3"}},
					ParentId: "spiffe:parent",
					SpiffeId: "spiffe:test2"},
				&common.RegistrationEntry{
					Selectors: selectors{&common.Selector{Type: "testtype1", Value: "testValue1"},
						&common.Selector{Type: "testtype1", Value: "testValue2"},
						&common.Selector{Type: "testtype1", Value: "testValue3"}},
					ParentId: "spiffe:parent",
					SpiffeId: "spiffe:test3"}},
			parentID: "spiffe:parent",
			expectedList: regEntries{
				&common.RegistrationEntry{
					Selectors: selectors{&common.Selector{Type: "testtype1", Value: "testValue1"},
						&common.Selector{Type: "testtype1", Value: "testValue2"},
						&common.Selector{Type: "testtype1", Value: "testValue3"}},
					ParentId: "spiffe:parent",
					SpiffeId: "spiffe:test1"},
				&common.RegistrationEntry{
					Selectors: selectors{&common.Selector{Type: "testtype1", Value: "testValue1"},
						&common.Selector{Type: "testtype1", Value: "testValue2"},
						&common.Selector{Type: "testtype1", Value: "testValue3"}},
					ParentId: "spiffe:parent",
					SpiffeId: "spiffe:test2"},
				&common.RegistrationEntry{
					Selectors: selectors{&common.Selector{Type: "testtype1", Value: "testValue1"},
						&common.Selector{Type: "testtype1", Value: "testValue2"},
						&common.Selector{Type: "testtype1", Value: "testValue3"}},
					ParentId: "spiffe:parent",
					SpiffeId: "spiffe:test3"}},
		},
		{

			name: "test_parentID_not_found",
			regEntrySameParentID: regEntries{
				&common.RegistrationEntry{
					Selectors: selectors{&common.Selector{Type: "testtype1", Value: "testValue1"},
						&common.Selector{Type: "testtype1", Value: "testValue2"},
						&common.Selector{Type: "testtype1", Value: "testValue3"}},
					ParentId: "spiffe:parent",
					SpiffeId: "spiffe:test1"},
				&common.RegistrationEntry{
					Selectors: selectors{&common.Selector{Type: "testtype1", Value: "testValue1"},
						&common.Selector{Type: "testtype1", Value: "testValue2"},
						&common.Selector{Type: "testtype1", Value: "testValue3"}},
					ParentId: "spiffe:parent",
					SpiffeId: "spiffe:test2"},
				&common.RegistrationEntry{
					Selectors: selectors{&common.Selector{Type: "testtype1", Value: "testValue1"},
						&common.Selector{Type: "testtype1", Value: "testValue2"},
						&common.Selector{Type: "testtype1", Value: "testValue3"}},
					ParentId: "spiffe:parent",
					SpiffeId: "spiffe:test3"}},
			parentID:     "spiffe:invalid",
			expectedList: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ds := createDefault(t)
			for _, entry := range test.regEntrySameParentID {
				ds.CreateRegistrationEntry(&datastore.CreateRegistrationEntryRequest{entry})
			}
			result, err := ds.ListParentIDEntries(&datastore.ListParentIDEntriesRequest{
				ParentId: test.parentID})
			require.NoError(t, err)
			assert.Equal(t, test.expectedList, result.RegisteredEntryList)
		})
	}
}

func Test_ListSelectorEntries(t *testing.T) {
	t.Skipf("TODO")
}

func Test_ListSpiffeEntriesEntry(t *testing.T) {
	t.Skipf("TODO")
}

func Test_Configure(t *testing.T) {
	t.Skipf("TODO")
}

func Test_GetPluginInfo(t *testing.T) {
	ds := createDefault(t)
	resp, err := ds.GetPluginInfo(&sriplugin.GetPluginInfoRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func Test_race(t *testing.T) {
	ds := createDefault(t)

	entry := &datastore.AttestedNodeEntry{
		BaseSpiffeId:       "foo",
		AttestedDataType:   "aws-tag",
		CertSerialNumber:   "badcafe",
		CertExpirationDate: time.Now().Add(time.Hour).Format(datastore.TimeFormat),
	}

	testutil.RaceTest(t, func(t *testing.T) {
		ds.CreateAttestedNodeEntry(&datastore.CreateAttestedNodeEntryRequest{entry})
		ds.FetchAttestedNodeEntry(&datastore.FetchAttestedNodeEntryRequest{entry.BaseSpiffeId})
	})
}

func createDefault(t *testing.T) datastore.DataStore {
	ds, err := New()
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

func getTestDataFromJsonFile(t *testing.T, filePath string, jsonValue interface{}) error {
	invalidRegistrationEntriesJson, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	err = json.Unmarshal(invalidRegistrationEntriesJson, &jsonValue)
	if err != nil {
		return err
	}

	return nil
}
