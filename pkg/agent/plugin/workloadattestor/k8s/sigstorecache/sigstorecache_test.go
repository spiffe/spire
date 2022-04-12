package sigstorecache

import (
	"container/list"
	"crypto/x509"
	"reflect"
	"sync"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/pkg/oci"
)

var (
	signature1 = Item{
		Key: "signature1",
		Value: []oci.Signature{
			signature{
				payload: []byte(`{
				"critical": {
					"identity": {
						"docker-reference": "docker-registry.com/some/image"},
						"image": {"docker-manifest-digest": "11111111111111"},
						"type": "some type"
					},
					"optional": {
						"subject": "spirex1@example.com"
						}
					},
				}`),
			},
		},
	}

	signature2 = Item{
		Key: "signature2",
		Value: []oci.Signature{
			signature{
				payload: []byte(`{
				"critical": {
					"identity": {
						"docker-reference": "docker-registry.com/some/image"},
						"image": {"docker-manifest-digest2": "2222222222222"},
						"type": "some type"
					},
					"optional": {
						"subject": "spirex2@example.com"
						},
					},
				},`),
			},
		},
	}

	signature3 = Item{
		Key: "signature3",
		Value: []oci.Signature{
			signature{
				payload: []byte(`{
							"critical": {
								"identity": {
									"docker-reference": "docker-registry.com/some/image"
								},
								"image": {
									"docker-manifest-digest3": "3333333333333"
								},
								"type": "some type"
							}
							"optional": {
								"subject": "spirex3@example.com"
							}
						}`),
			},
		},
	}

	signature3Updated = Item{
		Key: "signature3",
		Value: []oci.Signature{
			signature{
				payload: []byte(`{
								"critical": {
									"identity": {
										"docker-reference": "docker-registry.com/some/image"
									},
									"image": {
										"docker-manifest-digest4": "4444444444444"
									},
									"type": "some type"
								}
								"optional": {
									"subject": "spirex4@example.com"
								}
							}`),
			},
		},
	}
)

type signature struct {
	v1.Layer

	payload []byte
	cert    *x509.Certificate
	bundle  *oci.Bundle
}

func (signature) Annotations() (map[string]string, error) {
	return nil, nil
}

func (s signature) Payload() ([]byte, error) {
	return s.payload, nil
}

func (signature) Base64Signature() (string, error) {
	return "", nil
}

func (s signature) Cert() (*x509.Certificate, error) {
	return s.cert, nil
}

func (signature) Chain() ([]*x509.Certificate, error) {
	return nil, nil
}

func (s signature) Bundle() (*oci.Bundle, error) {
	return s.bundle, nil
}

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

	m[signature1.Key] = MapItem{
		item:    &signature1,
		element: items.PushFront(signature1.Key),
	}
	m[signature2.Key] = MapItem{
		item:    &signature2,
		element: items.PushFront(signature2.Key),
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
			key:          signature3.Key,
			errorMessage: "A non-existing item's key should return a nil item.",
		},
		{
			name:         "Existing entry",
			want:         &signature1,
			key:          signature1.Key,
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
			item:       &signature1,
			wantLength: 1,
			wantKey:    signature1.Key,
			wantValue:  &signature1,
		},
		{
			name:       "Put first element again",
			item:       &signature1,
			wantLength: 1,
			wantKey:    signature1.Key,
			wantValue:  &signature1,
		},
		{
			name:       "Put second element",
			item:       &signature2,
			wantLength: 2,
			wantKey:    signature2.Key,
			wantValue:  &signature2,
		},
		{
			name:       "Overflow cache",
			item:       &signature3,
			wantLength: 2,
			wantKey:    signature3.Key,
			wantValue:  &signature3,
		},
		{
			name:       "Update entry",
			item:       &signature3Updated,
			wantLength: 2,
			wantKey:    signature3.Key,
			wantValue:  &signature3Updated,
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
