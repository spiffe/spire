//go:build !windows
// +build !windows

package sigstore

import (
	"container/list"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	selectors1 = Item{
		Key: "signature1",
		Value: []SelectorsFromSignatures{
			{
				Subject:        "spirex1@example.com",
				Content:        "content1",
				LogID:          "1111111111111111",
				IntegratedTime: "1111111111111111",
			},
		},
	}

	selectors2 = Item{
		Key: "signature2",
		Value: []SelectorsFromSignatures{
			{
				Subject:        "spirex2@example.com",
				Content:        "content2",
				LogID:          "2222222222222222",
				IntegratedTime: "2222222222222222",
			},
		},
	}

	selectors3 = Item{
		Key: "signature3",
		Value: []SelectorsFromSignatures{
			{
				Subject:        "spirex3@example.com",
				Content:        "content3",
				LogID:          "3333333333333333",
				IntegratedTime: "3333333333333333",
			},
		},
	}

	selectors3Updated = Item{
		Key: "signature3",
		Value: []SelectorsFromSignatures{
			{
				Subject:        "spirex3@example.com",
				Content:        "content4",
				LogID:          "4444444444444444",
				IntegratedTime: "4444444444444444",
			},
		},
	}

	selectors2Updated = Item{
		Key: "signature2",
		Value: []SelectorsFromSignatures{
			{
				Subject:        "spirex2@example.com",
				Content:        "content5",
				LogID:          "5555555555555555",
				IntegratedTime: "5555555555555555",
			},
		},
	}
)

func TestNewCache(t *testing.T) {
	want := &cacheImpl{
		size:     3,
		items:    list.New(),
		mutex:    sync.RWMutex{},
		itemsMap: make(map[string]MapItem),
	}
	got := NewCache(3)
	require.Equal(t, want, got, "NewCache() = %v, want %v", got, want)
}

func TestCacheimpl_GetSignature(t *testing.T) {
	m := make(map[string]MapItem)
	items := list.New()

	m[selectors1.Key] = MapItem{
		item:    &selectors1,
		element: items.PushFront(selectors1.Key),
	}
	m[selectors2.Key] = MapItem{
		item:    &selectors2,
		element: items.PushFront(selectors2.Key),
	}

	cacheInstance := &cacheImpl{
		size:     3,
		items:    items,
		mutex:    sync.RWMutex{},
		itemsMap: m,
	}

	tests := []struct {
		name         string
		want         *Item
		key          string
		errorMessage string
	}{
		{
			name:         "Non existing entry",
			want:         nil,
			key:          selectors3.Key,
			errorMessage: "A non-existing item's key should return a nil item.",
		},
		{
			name:         "Existing entry",
			want:         &selectors1,
			key:          selectors1.Key,
			errorMessage: "An existing items key's should return the existing item",
		},
	}

	for _, tt := range tests {
		got := cacheInstance.GetSignature(tt.key)
		require.Equal(t, got, tt.want, "%v Got: %v Want: %v", tt.errorMessage, got, tt.want)
	}
}

func TestCacheimpl_PutSignature(t *testing.T) {
	m := make(map[string]MapItem)
	items := list.New()

	cacheInstance := &cacheImpl{
		size:     2,
		items:    items,
		mutex:    sync.RWMutex{},
		itemsMap: m,
	}

	tests := []struct {
		name       string
		item       *Item
		wantLength int
		wantKey    string
		wantValue  *Item
	}{
		{
			name:       "Put first element",
			item:       &selectors1,
			wantLength: 1,
			wantKey:    selectors1.Key,
			wantValue:  &selectors1,
		},
		{
			name:       "Put first element again",
			item:       &selectors1,
			wantLength: 1,
			wantKey:    selectors1.Key,
			wantValue:  &selectors1,
		},
		{
			name:       "Put second element",
			item:       &selectors2,
			wantLength: 2,
			wantKey:    selectors2.Key,
			wantValue:  &selectors2,
		},
		{
			name:       "Overflow cache",
			item:       &selectors3,
			wantLength: 2,
			wantKey:    selectors3.Key,
			wantValue:  &selectors3,
		},
		{
			name:       "Update entry",
			item:       &selectors3Updated,
			wantLength: 2,
			wantKey:    selectors3.Key,
			wantValue:  &selectors3Updated,
		},
	}

	for _, tt := range tests {
		cacheInstance.PutSignature(*tt.item)
		gotLen := cacheInstance.items.Len()
		if gotLen != tt.wantLength {
			t.Errorf("Item count should be %v in test case %q", tt.wantLength, tt.name)
		}
		gotItem, present := m[tt.wantKey]
		require.True(t, present, "key not found")
		require.Equal(t, gotItem.item, tt.wantValue, "Value different than expected. \nGot: %v \nWant:%v", gotItem.item, tt.wantValue)
	}
}

func TestCacheimpl_CheckOverflowAndUpdates(t *testing.T) {
	m := make(map[string]MapItem)
	items := list.New()

	cacheInstance := &cacheImpl{
		size:     2,
		items:    items,
		mutex:    sync.RWMutex{},
		itemsMap: m,
	}

	putSteps1 := []struct {
		name        string
		item        *Item
		wantLength  int
		wantKey     string
		wantValue   *Item
		wantHeadKey string
	}{
		{
			name:        "Put first element",
			item:        &selectors1,
			wantLength:  1,
			wantKey:     selectors1.Key,
			wantValue:   &selectors1,
			wantHeadKey: selectors1.Key,
		},
		{
			name:        "Put first element again",
			item:        &selectors1,
			wantLength:  1,
			wantKey:     selectors1.Key,
			wantValue:   &selectors1,
			wantHeadKey: selectors1.Key,
		},
		{
			name:        "Put second element",
			item:        &selectors2,
			wantLength:  2,
			wantKey:     selectors2.Key,
			wantValue:   &selectors2,
			wantHeadKey: selectors2.Key,
		},
		{
			name:        "Put third element, Overflow cache",
			item:        &selectors3,
			wantLength:  2,
			wantKey:     selectors3.Key,
			wantValue:   &selectors3,
			wantHeadKey: selectors3.Key,
		},
		{
			name:        "Update entry",
			item:        &selectors3Updated,
			wantLength:  2,
			wantKey:     selectors3.Key,
			wantValue:   &selectors3Updated,
			wantHeadKey: selectors3.Key,
		},
		{
			name:        "Put second element, again",
			item:        &selectors2,
			wantLength:  2,
			wantKey:     selectors2.Key,
			wantValue:   &selectors2,
			wantHeadKey: selectors2.Key,
		},
	}
	getSteps1 := []struct {
		name        string
		key         string
		item        *Item
		wantLength  int
		wantValue   *Item
		wantHeadKey string
	}{
		{
			name:        "Get first element",
			key:         selectors1.Key,
			item:        nil,
			wantLength:  2,
			wantHeadKey: selectors2.Key,
		},
		{
			name:        "Get third element",
			key:         selectors3.Key,
			item:        &selectors3Updated,
			wantLength:  2,
			wantHeadKey: selectors3.Key,
		},
		{
			name:        "Get first element, after third element was accessed",
			key:         selectors1.Key,
			item:        nil,
			wantLength:  2,
			wantHeadKey: selectors3.Key,
		},
		{
			name:        "Get second element",
			key:         selectors2.Key,
			item:        &selectors2,
			wantLength:  2,
			wantValue:   &selectors2,
			wantHeadKey: selectors2.Key,
		},
	}

	putSteps2 := []struct {
		name        string
		item        *Item
		wantLength  int
		wantKey     string
		wantValue   *Item
		wantHeadKey string
	}{
		{
			name:        "Put first element again, overflow cache",
			item:        &selectors1,
			wantLength:  2,
			wantKey:     selectors1.Key,
			wantValue:   &selectors1,
			wantHeadKey: selectors1.Key,
		},
		{
			name:        "Put second element updated",
			item:        &selectors2Updated,
			wantLength:  2,
			wantKey:     selectors2.Key,
			wantValue:   &selectors2Updated,
			wantHeadKey: selectors2.Key,
		},
		{
			name:        "Put third element again, overflow cache",
			item:        &selectors3Updated,
			wantLength:  2,
			wantKey:     selectors3.Key,
			wantValue:   &selectors3Updated,
			wantHeadKey: selectors3.Key,
		},
		{
			name:        "Revert third entry",
			item:        &selectors3,
			wantLength:  2,
			wantKey:     selectors3.Key,
			wantValue:   &selectors3,
			wantHeadKey: selectors3.Key,
		},
		{
			name:        "Pull second element to front",
			item:        &selectors2Updated,
			wantLength:  2,
			wantKey:     selectors2.Key,
			wantValue:   &selectors2Updated,
			wantHeadKey: selectors2.Key,
		},
		{
			name:        "Put first element for the last time, overflow cache",
			item:        &selectors1,
			wantLength:  2,
			wantKey:     selectors1.Key,
			wantValue:   &selectors1,
			wantHeadKey: selectors1.Key,
		},
	}

	getSteps2 := []struct {
		name        string
		key         string
		item        *Item
		wantLength  int
		wantValue   *Item
		wantHeadKey string
	}{
		{
			name:        "Get third element, should fail",
			key:         selectors3.Key,
			item:        nil,
			wantLength:  2,
			wantHeadKey: selectors1.Key,
		},
		{
			name:        "Get third element again, should not change head",
			key:         selectors3.Key,
			item:        nil,
			wantLength:  2,
			wantHeadKey: selectors1.Key,
		},
		{
			name:        "Get first element",
			key:         selectors1.Key,
			item:        &selectors1,
			wantLength:  2,
			wantHeadKey: selectors1.Key,
		},
		{
			name:        "Get second element",
			key:         selectors2.Key,
			item:        &selectors2Updated,
			wantLength:  2,
			wantHeadKey: selectors2.Key,
		},
		{
			name:        "Get third element again, should have new head from last get",
			key:         selectors3.Key,
			item:        nil,
			wantLength:  2,
			wantHeadKey: selectors2.Key,
		},
	}

	for _, step := range putSteps1 {
		cacheInstance.PutSignature(*step.item)
		require.Contains(t, m, step.wantKey, "Key %q should be in the map after step %q", step.wantKey, step.name)
		gotItem := m[step.wantKey].item

		require.Equal(t, gotItem, step.wantValue, "Value different than expected. \nGot: %v \nWant:%v", gotItem, step.wantValue)
		require.Equal(t, items.Len(), step.wantLength, "Item count should be %v after step %q", step.wantLength, step.name)
		require.Equal(t, items.Front().Value, step.wantHeadKey, "First element is %v should be %v after step %q", items.Front().Value, step.wantHeadKey, step.name)
	}
	for _, step := range getSteps1 {
		gotItem := cacheInstance.GetSignature(step.key)

		require.Equal(t, gotItem, step.item, "Value different than expected. \nGot: %v \nWant:%v", gotItem, step.item)
		require.Equal(t, items.Len(), step.wantLength, "Item count should be %v after step %q", step.wantLength, step.name)
		require.Equal(t, items.Front().Value, step.wantHeadKey, "First element is %v should be %v after step %q", items.Front().Value, step.wantHeadKey, step.name)
	}
	for _, step := range putSteps2 {
		cacheInstance.PutSignature(*step.item)
		require.Contains(t, m, step.wantKey, "Key %q should be in the map after step %q", step.wantKey, step.name)
		gotItem := m[step.wantKey].item

		require.Equal(t, gotItem, step.wantValue, "Value different than expected. \nGot: %v \nWant:%v", gotItem, step.wantValue)
		require.Equal(t, items.Len(), step.wantLength, "Item count should be %v after step %q", step.wantLength, step.name)
		require.Equal(t, items.Front().Value, step.wantHeadKey, "First element is %v should be %v after step %q", items.Front().Value, step.wantHeadKey, step.name)
	}
	for _, step := range getSteps2 {
		gotItem := cacheInstance.GetSignature(step.key)

		require.Equal(t, gotItem, step.item, "Value different than expected. \nGot: %v \nWant:%v", gotItem, step.item)
		require.Equal(t, items.Len(), step.wantLength, "Item count should be %v after step %q", step.wantLength, step.name)
		require.Equal(t, items.Front().Value, step.wantHeadKey, "First element is %v should be %v after step %q", items.Front().Value, step.wantHeadKey, step.name)
	}
}
