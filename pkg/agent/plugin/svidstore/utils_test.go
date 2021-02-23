package svidstore_test

import (
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/require"
)

func TestParseSelectors(t *testing.T) {
	for _, tt := range []struct {
		name       string
		expect     map[string]string
		pluginName string
		selectors  []*common.Selector
	}{
		{
			name:       "multiples selectors",
			pluginName: "t",
			selectors: []*common.Selector{
				{Type: "t", Value: "a:1"},
				{Type: "t", Value: "b:2"},
				{Type: "t", Value: "c:3"},
			},
			expect: map[string]string{
				"a": "1",
				"b": "2",
				"c": "3",
			},
		},
		{
			name:       "selectors filtered by type",
			pluginName: "t",
			selectors: []*common.Selector{
				{Type: "t", Value: "a:1"},
				{Type: "t", Value: "b:2"},
				{Type: "s", Value: "c:3"},
			},
			expect: map[string]string{
				"a": "1",
				"b": "2",
			},
		},
		{
			name:       "no selectors",
			pluginName: "t",
			selectors:  []*common.Selector{},
			expect:     map[string]string{},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			result := svidstore.ParseSelectors(tt.pluginName, tt.selectors)
			require.Equal(t, tt.expect, result)
		})
	}
}

func TestEncodeSecret(t *testing.T) {
	for _, tt := range []struct {
		name   string
		req    *svidstore.PutX509SVIDRequest
		err    string
		expect *svidstore.X509Response
	}{
		{
			name: "success",
			req: &svidstore.PutX509SVIDRequest{
				Svid: &svidstore.X509SVID{
					SpiffeId:   "spiffe://example.org/foo",
					CertChain:  []byte("foo"),
					PrivateKey: []byte("bar"),
					Bundle:     []byte("baz"),
					ExpiresAt:  123456,
				},
				Selectors: []*common.Selector{
					{Type: "t", Value: "a:1"},
					{Type: "t", Value: "b:2"},
				},
				FederatedBundles: map[string][]byte{
					"federated1": {1},
					"federated2": {2},
				},
			},
			expect: &svidstore.X509Response{
				SpiffeID: "spiffe://example.org/foo",
				Svid:     [][]byte{[]byte("foo")},
				Key:      []byte("bar"),
				Bundles: map[string][]byte{
					"spiffe://example.org": []byte("baz"),
					"federated1":           {1},
					"federated2":           {2},
				},
			},
		},
		{
			name: "malformed SpiffeID",
			err:  "failed to get trustdomain from SPIFFE ID: spiffeid: unable to parse: parse \"spiffe://no an id\": invalid character \" \" in host name",
			req: &svidstore.PutX509SVIDRequest{
				Svid: &svidstore.X509SVID{
					SpiffeId:   "no an id",
					CertChain:  []byte("foo"),
					PrivateKey: []byte("bar"),
					Bundle:     []byte("baz"),
					ExpiresAt:  123456,
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svidstore.X509ResponseFromProto(tt.req)
			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expect, resp)
		})
	}
}
