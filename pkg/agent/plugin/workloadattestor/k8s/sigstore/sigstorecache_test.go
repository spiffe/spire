package sigstore

import (
	"container/list"
	"reflect"
	"sync"
	"testing"
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
)

func TestNewCache(t *testing.T) {
	tests := []struct {
		name string
		want Cache
	}{
		{
			name: "New",
			want: &Cacheimpl{
				size:     3,
				items:    list.New(),
				mutex:    sync.RWMutex{},
				itensMap: make(map[string]MapItem),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewCache(3); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewCache() = %v, want %v", got, tt.want)
			}
		})
	}
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

	cacheInstance := &Cacheimpl{
		size:     3,
		items:    items,
		mutex:    sync.RWMutex{},
		itensMap: m,
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
		t.Run(tt.name, func(t *testing.T) {
			if got := cacheInstance.GetSignature(tt.key); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("%v Got: %v Want: %v", tt.errorMessage, got, tt.want)
			}
		})
	}
}

func TestCacheimpl_PutSignature(t *testing.T) {
	m := make(map[string]MapItem)
	items := list.New()

	cacheInstance := &Cacheimpl{
		size:     2,
		items:    items,
		mutex:    sync.RWMutex{},
		itensMap: m,
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

	putKeys := 0
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheInstance.PutSignature(*tt.item)
			putKeys++
			gotLen := cacheInstance.items.Len()
			if gotLen != tt.wantLength {
				t.Errorf("Item count should be %v after putting %v keys", tt.wantLength, putKeys)
			}
			gotItem, present := m[tt.wantKey]
			if !present {
				t.Errorf("Key put but not found: %v", tt.wantKey)
			}

			if !reflect.DeepEqual(gotItem.item, tt.wantValue) {
				t.Errorf("Value different than expected. \nGot: %v \nWant:%v", gotItem.item, tt.wantValue)
			}
		})
	}
}
