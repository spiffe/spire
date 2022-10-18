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
	m, items := makeMapAndList(&selectors1, &selectors2)
	cacheInstance := &cacheImpl{
		size:     3,
		items:    items,
		mutex:    sync.RWMutex{},
		itemsMap: m,
	}

	caseInOrderList := list.New()
	caseInOrderList.PushFront(selectors1.Key)
	caseInOrderList.PushFront(selectors2.Key)

	caseReorderList := list.New()
	caseReorderList.PushFront(selectors2.Key)
	caseReorderList.PushFront(selectors1.Key)

	tests := []struct {
		name         string
		want         *Item
		key          string
		errorMessage string
		wantedMap    map[string]MapItem
		wantedList   *list.List
	}{
		{
			name:         "Non existing entry",
			want:         nil,
			key:          selectors3.Key,
			errorMessage: "A non-existing item's key should return a nil item.",
			wantedMap: map[string]MapItem{
				"signature1": {item: &selectors1, element: m[selectors1.Key].element},
				"signature2": {item: &selectors2, element: m[selectors2.Key].element},
			},
			wantedList: caseInOrderList,
		},
		{
			name: "Existing entry",
			want: &selectors2,
			key:  selectors2.Key,
			wantedMap: map[string]MapItem{
				"signature1": {item: &selectors1, element: m[selectors1.Key].element},
				"signature2": {item: &selectors2, element: m[selectors2.Key].element},
			},
			wantedList: caseInOrderList,
		},
		{
			name: "Existing entry, reorder on get",
			want: &selectors1,
			key:  selectors1.Key,
			wantedMap: map[string]MapItem{
				"signature1": {item: &selectors1, element: m[selectors1.Key].element},
				"signature2": {item: &selectors2, element: m[selectors2.Key].element},
			},
			wantedList: caseReorderList,
		},
	}

	for _, tt := range tests {
		got := cacheInstance.GetSignature(tt.key)
		require.Equal(t, got, tt.want, "%v Got: %v Want: %v", tt.errorMessage, got, tt.want)
		require.Equal(t, tt.wantedList, cacheInstance.items, "Lists are different Got: %v Want: %v", cacheInstance.items, tt.wantedList)
		require.Equal(t, tt.wantedMap, cacheInstance.itemsMap, "Maps are different Got: %v Want: %v", cacheInstance.itemsMap, tt.wantedMap)
	}
}

func TestCacheimpl_PutSignature(t *testing.T) {
	mapReorder, listReorder := makeMapAndList(&selectors2, &selectors3)
	mapAddNew, listAddNew := makeMapAndList(&selectors3, &selectors2, &selectors1)
	mapUpdate, listUpdate := makeMapAndList(&selectors3, &selectors2Updated)
	mapReorderUpdate, listReorderUpdate := makeMapAndList(&selectors2, &selectors3Updated)
	tests := []struct {
		name       string
		item       *Item
		wantLength int
		wantKey    string
		wantValue  *Item
		wantMap    map[string]MapItem
		wantList   *list.List
	}{
		{
			name:       "Put existing element",
			item:       &selectors3,
			wantLength: 2,
			wantKey:    selectors3.Key,
			wantValue:  &selectors3,
			wantMap:    mapReorder,
			wantList:   listReorder,
		},
		{
			name:       "Put new element",
			item:       &selectors1,
			wantLength: 3,
			wantKey:    selectors1.Key,
			wantValue:  &selectors1,
			wantMap:    mapAddNew,
			wantList:   listAddNew,
		},
		{
			name:       "Update entry",
			item:       &selectors2Updated,
			wantLength: 2,
			wantKey:    selectors2.Key,
			wantValue:  &selectors2Updated,
			wantMap:    mapUpdate,
			wantList:   listUpdate,
		},
		{
			name:       "Update entry, reorder",
			item:       &selectors3Updated,
			wantLength: 2,
			wantKey:    selectors3.Key,
			wantValue:  &selectors3Updated,
			wantMap:    mapReorderUpdate,
			wantList:   listReorderUpdate,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			testMap, testItems := makeMapAndList(&selectors3, &selectors2)
			cacheInstance := cacheImpl{
				size:     10,
				items:    testItems,
				mutex:    sync.RWMutex{},
				itemsMap: testMap,
			}
			cacheInstance.PutSignature(*tt.item)

			gotItem, present := testMap[tt.wantKey]
			require.True(t, present, "key not found")
			require.Equal(t, tt.wantValue, gotItem.item, "Value different than expected. \nGot: %v \nWant:%v", gotItem.item, tt.wantValue)
			require.Equal(t, tt.wantLength, testItems.Len(), "List length different than expected. \nGot: %v \nWant:%v", testItems.Len(), tt.wantLength)
			require.Equal(t, tt.wantList, testItems, "Lists are different Got: %v Want: %v", testItems, tt.wantList)
			require.Equal(t, tt.wantMap, testMap, "Maps are different Got: %v Want: %v", testMap, tt.wantMap)
		})
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

func TestCacheimpl_CheckOverflow(t *testing.T) {
	mapNoOverflow, listNoOverflow := makeMapAndList(&selectors1, &selectors2, &selectors3)
	mapOverflow, listOverflow := makeMapAndList(&selectors2, &selectors3)
	mapReorder, listReorder := makeMapAndList(&selectors2, &selectors1)

	testCases := []struct {
		name       string
		item       *Item
		wantLength int
		wantedList *list.List
		wantedMap  map[string]MapItem
		maxLength  int
	}{
		{
			name:       "Put third element, no overflow",
			item:       &selectors3,
			wantedList: listNoOverflow,
			wantedMap:  mapNoOverflow,
			maxLength:  3,
		},
		{
			name:       "Put existing element no overflow",
			item:       &selectors1,
			wantedList: listReorder,
			wantedMap:  mapReorder,
			maxLength:  2,
		},
		{
			name:       "Put third element, overflow",
			item:       &selectors3,
			wantedList: listOverflow,
			wantedMap:  mapOverflow,
			maxLength:  2,
		},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
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
				size:     testCase.maxLength,
				items:    items,
				mutex:    sync.RWMutex{},
				itemsMap: m,
			}
			cacheInstance.PutSignature(*testCase.item)
			require.Equal(t, testCase.wantedList, cacheInstance.items, "List different than expected. \nGot: %v \nWant:%v", cacheInstance.items, testCase.wantedList)
			require.Equal(t, testCase.wantedMap, cacheInstance.itemsMap, "Map different than expected. \nGot: %v \nWant:%v", cacheInstance.itemsMap, testCase.wantedMap)
		})
	}
}

func makeMapAndList(items ...*Item) (map[string]MapItem, *list.List) {
	mp := make(map[string]MapItem)
	ls := list.New()
	for _, item := range items {
		mp[item.Key] = MapItem{
			item:    item,
			element: ls.PushFront(item.Key),
		}
	}
	return mp, ls
}
