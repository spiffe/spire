package main

import (
	"testing"
	"time"

	common "github.com/spiffe/sri/control_plane/plugins/common/proto"
	datastore "github.com/spiffe/sri/control_plane/plugins/data_store"
	"github.com/spiffe/sri/control_plane/plugins/data_store/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFederatedEntry_CRUD(t *testing.T) {
	ds := createDefault(t)

	bundle := &control_plane_proto.FederatedBundle{
		FederatedBundleSpiffeId: "foo",
		FederatedTrustBundle:    []byte("bar"),
		Ttl:                     10,
	}

	// create
	_, err := ds.CreateFederatedEntry(&control_plane_proto.CreateFederatedEntryRequest{bundle})
	require.NoError(t, err)

	// list
	lresp, err := ds.ListFederatedEntry(&control_plane_proto.ListFederatedEntryRequest{})
	require.NoError(t, err)
	assert.Equal(t, []string{bundle.FederatedBundleSpiffeId}, lresp.FederatedBundleSpiffeIdList)

	// update
	bundle2 := &control_plane_proto.FederatedBundle{
		FederatedBundleSpiffeId: bundle.FederatedBundleSpiffeId,
		FederatedTrustBundle:    []byte("baz"),
		Ttl:                     20,
	}

	uresp, err := ds.UpdateFederatedEntry(&control_plane_proto.UpdateFederatedEntryRequest{bundle2})
	require.NoError(t, err)
	assert.Equal(t, bundle2, uresp.FederatedBundle)

	lresp, err = ds.ListFederatedEntry(&control_plane_proto.ListFederatedEntryRequest{})
	require.NoError(t, err)
	assert.Equal(t, []string{bundle.FederatedBundleSpiffeId}, lresp.FederatedBundleSpiffeIdList)

	// delete
	dresp, err := ds.DeleteFederatedEntry(&control_plane_proto.DeleteFederatedEntryRequest{
		FederatedBundleSpiffeId: bundle.FederatedBundleSpiffeId,
	})
	require.NoError(t, err)
	assert.Equal(t, bundle2, dresp.FederatedBundle)

	lresp, err = ds.ListFederatedEntry(&control_plane_proto.ListFederatedEntryRequest{})
	require.NoError(t, err)
	assert.Len(t, lresp.FederatedBundleSpiffeIdList, 0)
}

func Test_ListFederatedEntry(t *testing.T) {
	ds := createDefault(t)

	lresp, err := ds.ListFederatedEntry(&control_plane_proto.ListFederatedEntryRequest{})
	require.NoError(t, err)
	assert.Empty(t, lresp.FederatedBundleSpiffeIdList)
}

//

func Test_CreateAttestedNodeEntry(t *testing.T) {
	ds := createDefault(t)

	entry := &control_plane_proto.AttestedNodeEntry{
		BaseSpiffeId:       "foo",
		AttestedDataType:   "aws-tag",
		CertSerialNumber:   "badcafe",
		CertExpirationDate: time.Now().Add(time.Hour).Format(datastore.TimeFormat),
	}

	cresp, err := ds.CreateAttestedNodeEntry(&control_plane_proto.CreateAttestedNodeEntryRequest{entry})
	require.NoError(t, err)
	assert.Equal(t, entry, cresp.AttestedNodeEntry)

	fresp, err := ds.FetchAttestedNodeEntry(&control_plane_proto.FetchAttestedNodeEntryRequest{entry.BaseSpiffeId})
	require.NoError(t, err)
	assert.Equal(t, entry, fresp.AttestedNodeEntry)

	sresp, err := ds.FetchStaleNodeEntries(&control_plane_proto.FetchStaleNodeEntriesRequest{})
	require.NoError(t, err)
	assert.Empty(t, sresp.AttestedNodeEntryList)
}

func Test_FetchAttestedNodeEntry_missing(t *testing.T) {
	ds := createDefault(t)
	fresp, err := ds.FetchAttestedNodeEntry(&control_plane_proto.FetchAttestedNodeEntryRequest{"missing"})
	require.NoError(t, err)
	require.Nil(t, fresp.AttestedNodeEntry)
}

func Test_FetchStaleNodeEntries(t *testing.T) {
	ds := createDefault(t)

	efuture := &control_plane_proto.AttestedNodeEntry{
		BaseSpiffeId:       "foo",
		AttestedDataType:   "aws-tag",
		CertSerialNumber:   "badcafe",
		CertExpirationDate: time.Now().Add(time.Hour).Format(datastore.TimeFormat),
	}

	epast := &control_plane_proto.AttestedNodeEntry{
		BaseSpiffeId:       "bar",
		AttestedDataType:   "aws-tag",
		CertSerialNumber:   "deadbeef",
		CertExpirationDate: time.Now().Add(-time.Hour).Format(datastore.TimeFormat),
	}

	_, err := ds.CreateAttestedNodeEntry(&control_plane_proto.CreateAttestedNodeEntryRequest{efuture})
	require.NoError(t, err)

	_, err = ds.CreateAttestedNodeEntry(&control_plane_proto.CreateAttestedNodeEntryRequest{epast})
	require.NoError(t, err)

	sresp, err := ds.FetchStaleNodeEntries(&control_plane_proto.FetchStaleNodeEntriesRequest{})
	require.NoError(t, err)
	assert.Equal(t, []*control_plane_proto.AttestedNodeEntry{epast}, sresp.AttestedNodeEntryList)
}

func Test_UpdateAttestedNodeEntry(t *testing.T) {
	ds := createDefault(t)

	entry := &control_plane_proto.AttestedNodeEntry{
		BaseSpiffeId:       "foo",
		AttestedDataType:   "aws-tag",
		CertSerialNumber:   "badcafe",
		CertExpirationDate: time.Now().Add(time.Hour).Format(datastore.TimeFormat),
	}

	userial := "deadbeef"
	uexpires := time.Now().Add(time.Hour * 2).Format(datastore.TimeFormat)

	_, err := ds.CreateAttestedNodeEntry(&control_plane_proto.CreateAttestedNodeEntryRequest{entry})
	require.NoError(t, err)

	uresp, err := ds.UpdateAttestedNodeEntry(&control_plane_proto.UpdateAttestedNodeEntryRequest{
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

	fresp, err := ds.FetchAttestedNodeEntry(&control_plane_proto.FetchAttestedNodeEntryRequest{entry.BaseSpiffeId})
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

	entry := &control_plane_proto.AttestedNodeEntry{
		BaseSpiffeId:       "foo",
		AttestedDataType:   "aws-tag",
		CertSerialNumber:   "badcafe",
		CertExpirationDate: time.Now().Add(time.Hour).Format(datastore.TimeFormat),
	}

	_, err := ds.CreateAttestedNodeEntry(&control_plane_proto.CreateAttestedNodeEntryRequest{entry})
	require.NoError(t, err)

	dresp, err := ds.DeleteAttestedNodeEntry(&control_plane_proto.DeleteAttestedNodeEntryRequest{entry.BaseSpiffeId})
	require.NoError(t, err)
	assert.Equal(t, entry, dresp.AttestedNodeEntry)

	fresp, err := ds.FetchAttestedNodeEntry(&control_plane_proto.FetchAttestedNodeEntryRequest{entry.BaseSpiffeId})
	require.NoError(t, err)
	assert.Nil(t, fresp.AttestedNodeEntry)
}

//

func Test_CreateNodeResolverMapEntry(t *testing.T) {
	ds := createDefault(t)

	entry := &control_plane_proto.NodeResolverMapEntry{
		BaseSpiffeId: "main",
		Selector: &control_plane_proto.Selector{
			Type:  "aws-tag",
			Value: "a",
		},
	}

	cresp, err := ds.CreateNodeResolverMapEntry(&control_plane_proto.CreateNodeResolverMapEntryRequest{entry})
	require.NoError(t, err)

	centry := cresp.NodeResolverMapEntry
	assert.Equal(t, entry, centry)
}

func Test_CreateNodeResolverMapEntry_dupe(t *testing.T) {
	ds := createDefault(t)
	entries := createNodeResolverMapEntries(t, ds)

	entry := entries[0]
	cresp, err := ds.CreateNodeResolverMapEntry(&control_plane_proto.CreateNodeResolverMapEntryRequest{entry})
	assert.Error(t, err)
	require.Nil(t, cresp)
}

func Test_FetchNodeResolverMapEntry(t *testing.T) {
	ds := createDefault(t)

	entry := &control_plane_proto.NodeResolverMapEntry{
		BaseSpiffeId: "main",
		Selector: &control_plane_proto.Selector{
			Type:  "aws-tag",
			Value: "a",
		},
	}

	cresp, err := ds.CreateNodeResolverMapEntry(&control_plane_proto.CreateNodeResolverMapEntryRequest{entry})
	require.NoError(t, err)

	centry := cresp.NodeResolverMapEntry
	assert.Equal(t, entry, centry)
}

func Test_DeleteNodeResolverMapEntry_specific(t *testing.T) {
	// remove entries for the specific (spiffe_id,type,value)

	ds := createDefault(t)
	entries := createNodeResolverMapEntries(t, ds)

	entry_removed := entries[0]

	dresp, err := ds.DeleteNodeResolverMapEntry(&control_plane_proto.DeleteNodeResolverMapEntryRequest{entry_removed})
	require.NoError(t, err)

	assert.Equal(t, entries[0:1], dresp.NodeResolverMapEntryList)

	for idx, entry := range entries[1:] {
		fresp, err := ds.FetchNodeResolverMapEntry(&control_plane_proto.FetchNodeResolverMapEntryRequest{entry.BaseSpiffeId})
		require.NoError(t, err, idx)
		require.Len(t, fresp.NodeResolverMapEntryList, 1, "%v", idx)
		assert.Equal(t, entry, fresp.NodeResolverMapEntryList[0], "%v", idx)
	}
}

func Test_DeleteNodeResolverMapEntry_all(t *testing.T) {
	// remove all entries for the spiffe_id

	ds := createDefault(t)
	entries := createNodeResolverMapEntries(t, ds)

	entry_removed := &control_plane_proto.NodeResolverMapEntry{
		BaseSpiffeId: entries[0].BaseSpiffeId,
	}

	dresp, err := ds.DeleteNodeResolverMapEntry(&control_plane_proto.DeleteNodeResolverMapEntryRequest{entry_removed})
	require.NoError(t, err)

	assert.Equal(t, entries[0:2], dresp.NodeResolverMapEntryList)

	{
		entry := entry_removed
		fresp, err := ds.FetchNodeResolverMapEntry(&control_plane_proto.FetchNodeResolverMapEntryRequest{entry.BaseSpiffeId})
		require.NoError(t, err)
		assert.Empty(t, fresp.NodeResolverMapEntryList)
	}

	{
		entry := entries[2]
		fresp, err := ds.FetchNodeResolverMapEntry(&control_plane_proto.FetchNodeResolverMapEntryRequest{entry.BaseSpiffeId})
		require.NoError(t, err)
		assert.NotEmpty(t, fresp.NodeResolverMapEntryList)
	}
}

func Test_RectifyNodeResolverMapEntries(t *testing.T) {
}

func createNodeResolverMapEntries(t *testing.T, ds datastore.DataStore) []*control_plane_proto.NodeResolverMapEntry {
	entries := []*control_plane_proto.NodeResolverMapEntry{
		{
			BaseSpiffeId: "main",
			Selector: &control_plane_proto.Selector{
				Type:  "aws-tag",
				Value: "a",
			},
		},
		{
			BaseSpiffeId: "main",
			Selector: &control_plane_proto.Selector{
				Type:  "aws-tag",
				Value: "b",
			},
		},
		{
			BaseSpiffeId: "other",
			Selector: &control_plane_proto.Selector{
				Type:  "aws-tag",
				Value: "a",
			},
		},
	}

	for idx, entry := range entries {
		_, err := ds.CreateNodeResolverMapEntry(&control_plane_proto.CreateNodeResolverMapEntryRequest{entry})
		require.NoError(t, err, "%v", idx)
	}

	return entries
}

//

func Test_CreateRegistrationEntry(t *testing.T) {
	t.Skipf("TODO")
}

func Test_FetchRegistrationEntry(t *testing.T) {
	t.Skipf("TODO")
}

func Test_UpdateRegistrationEntry(t *testing.T) {
	t.Skipf("TODO")
}

func Test_DeleteRegistrationEntry(t *testing.T) {
	t.Skipf("TODO")
}

//

func Test_ListParentIDEntries(t *testing.T) {
	t.Skipf("TODO")
}

func Test_ListSelectorEntries(t *testing.T) {
	t.Skipf("TODO")
}

func Test_ListSpiffeEntriesEntry(t *testing.T) {
	t.Skipf("TODO")
}

//

func Test_Configure(t *testing.T) {
	t.Skipf("TODO")
}

func Test_GetPluginInfo(t *testing.T) {
	ds := createDefault(t)
	resp, err := ds.GetPluginInfo(&common.GetPluginInfoRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func createDefault(t *testing.T) datastore.DataStore {
	ds, err := New()
	if err != nil {
		t.Fatal(err)
	}
	return ds
}
