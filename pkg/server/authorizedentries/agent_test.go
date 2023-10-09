package authorizedentries

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAgentRecordSize(t *testing.T) {
	// The motivation for this test is to bring awareness and visibility into
	// how much size the record occupies. We want to minimize the size to
	// increase cache locality in the btree.
	require.Equal(t, uintptr(32), unsafe.Sizeof(agentRecord{}))
}

func TestAgentRecordByID(t *testing.T) {
	assertLess := func(lesser, greater agentRecord) {
		t.Helper()
		assert.Truef(t, agentRecordByID(lesser, greater), "expected A%sE%s<A%sE%s", lesser.ID, lesser.ExpiresAt, greater.ID, greater.ExpiresAt)
		assert.Falsef(t, agentRecordByID(greater, lesser), "expected A%sE%s>A%sE%s", greater.ID, greater.ExpiresAt, lesser.ID, lesser.ExpiresAt)
	}

	// ExpiresAt is irrelevant.
	records := []agentRecord{
		agentRecord{ID: "1", ExpiresAt: 9999},
		agentRecord{ID: "2", ExpiresAt: 8888},
	}

	lesser := agentRecord{}
	for _, greater := range records {
		assertLess(lesser, greater)
		lesser = greater
	}

	// Since there should only be one agent record by ID, the ExpiresAt field
	// is ignored for purposes of placement in the btree.
	assert.False(t, agentRecordByID(agentRecord{ID: "FOO", ExpiresAt: 1}, agentRecord{ID: "FOO", ExpiresAt: 2}))
	assert.False(t, agentRecordByID(agentRecord{ID: "FOO", ExpiresAt: 2}, agentRecord{ID: "FOO", ExpiresAt: 1}))
}

func TestAgentRecordByExpiresAt(t *testing.T) {
	assertLess := func(lesser, greater agentRecord) {
		t.Helper()
		assert.Truef(t, agentRecordByExpiresAt(lesser, greater), "expected A%sE%d<A%sE%d", lesser.ID, lesser.ExpiresAt, greater.ID, greater.ExpiresAt)
		assert.Falsef(t, agentRecordByExpiresAt(greater, lesser), "expected A%sE%d>A%sE%d", greater.ID, greater.ExpiresAt, lesser.ID, lesser.ExpiresAt)
	}

	records := []agentRecord{
		agentRecord{ID: "1"},
		agentRecord{ID: "2"},
		agentRecord{ID: "1", ExpiresAt: 1},
		agentRecord{ID: "2", ExpiresAt: 1},
		agentRecord{ID: "1", ExpiresAt: 2},
		agentRecord{ID: "2", ExpiresAt: 2},
	}

	lesser := agentRecord{}
	for _, greater := range records {
		assertLess(lesser, greater)
		lesser = greater
	}
}
