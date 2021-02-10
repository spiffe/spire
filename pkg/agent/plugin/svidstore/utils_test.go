package svidstore_test

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
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
		expect *workload.X509SVIDResponse
	}{
		{
			name: "success",
			req: &svidstore.PutX509SVIDRequest{
				Svid: &svidstore.X509SVID{
					SpiffeId:   "someID",
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
			expect: &workload.X509SVIDResponse{
				Svids: []*workload.X509SVID{
					{
						SpiffeId:    "someID",
						X509Svid:    []byte("foo"),
						X509SvidKey: []byte("bar"),
						Bundle:      []byte("baz"),
					},
				},
				FederatedBundles: map[string][]byte{
					"federated1": {1},
					"federated2": {2},
				},
			},
		},
		{
			name: "no svid provided",
			err:  "request does not contains a SVID",
			req: &svidstore.PutX509SVIDRequest{
				Selectors: []*common.Selector{
					{Type: "t", Value: "a:1"},
					{Type: "t", Value: "b:2"},
				},
				FederatedBundles: map[string][]byte{
					"federated1": {1},
					"federated2": {2},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			b, err := svidstore.EncodeSecret(tt.req)
			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				return
			}
			require.NoError(t, err)

			var m workload.X509SVIDResponse
			err = proto.Unmarshal(b, &m)
			require.NoError(t, err)

			spiretest.RequireProtoEqual(t, tt.expect, &m)
		})
	}
}
