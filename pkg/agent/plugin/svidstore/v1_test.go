package svidstore_test

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	svidstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/svidstore/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestV1DeleteX509SVID(t *testing.T) {
	svidValues := []string{"a:1", "b:2"}

	expectRequest := &svidstorev1.DeleteX509SVIDRequest{
		Metadata: []string{"a:1", "b:2"},
	}

	t.Run("delete fails", func(t *testing.T) {
		fake := &fakePluginV1{t: t}
		svidStore := makeFakeV1Plugin(fake)
		err := svidStore.DeleteX509SVID(context.Background(), []string{})
		spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "svidstore(test): oh no!")
	})

	t.Run("deleted successfully", func(t *testing.T) {
		fake := &fakePluginV1{t: t, expectDeleteRequest: expectRequest}
		svidStore := makeFakeV1Plugin(fake)
		err := svidStore.DeleteX509SVID(context.Background(), svidValues)
		assert.NoError(t, err)
	})
}

func TestV1PutX509SVID(t *testing.T) {
	expiresAt := time.Now().Add(time.Minute)
	key := testkey.MustEC256()
	keyData, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	federatedBundles := map[string][]*x509.Certificate{
		"td1": {
			{Raw: []byte{1}},
		},
		"td2": {
			{Raw: []byte{2}},
		},
	}

	svid := &svidstore.SVID{
		SPIFFEID: spiffeid.RequireFromString("spiffe://example.org/workload"),
		CertChain: []*x509.Certificate{
			{Raw: []byte{1}},
			{Raw: []byte{3}},
		},
		Bundle: []*x509.Certificate{
			{Raw: []byte{4}},
		},
		ExpiresAt:  expiresAt,
		PrivateKey: key,
	}

	for _, tt := range []struct {
		name             string
		expectPutRequest *svidstorev1.PutX509SVIDRequest
		expectCode       codes.Code
		expectMsgPrefix  string
		x509SVID         *svidstore.X509SVID
	}{
		{
			name: "success",
			expectPutRequest: &svidstorev1.PutX509SVIDRequest{
				Svid: &svidstorev1.X509SVID{
					SpiffeID:   "spiffe://example.org/workload",
					PrivateKey: keyData,
					CertChain:  [][]byte{{1}, {3}},
					Bundle:     [][]byte{{4}},
					ExpiresAt:  expiresAt.Unix(),
				},
				Metadata: []string{"a:1", "b:2"},
				FederatedBundles: map[string][]byte{
					"td1": {1},
					"td2": {2},
				},
			},
			x509SVID: &svidstore.X509SVID{
				FederatedBundles: federatedBundles,
				SVID:             svid,
				Metadata:         []string{"a:1", "b:2"},
			},
		},
		{
			name: "no federated bundles",
			expectPutRequest: &svidstorev1.PutX509SVIDRequest{
				Svid: &svidstorev1.X509SVID{
					SpiffeID:   "spiffe://example.org/workload",
					PrivateKey: keyData,
					CertChain:  [][]byte{{1}, {3}},
					Bundle:     [][]byte{{4}},
					ExpiresAt:  expiresAt.Unix(),
				},
				Metadata: []string{"a:1", "b:2"},
			},
			x509SVID: &svidstore.X509SVID{
				SVID:     svid,
				Metadata: []string{"a:1", "b:2"},
			},
		},
		{
			name: "fail to marshal key",
			x509SVID: &svidstore.X509SVID{
				FederatedBundles: federatedBundles,
				SVID: &svidstore.SVID{
					SPIFFEID: spiffeid.RequireFromString("spiffe://example.org/workload"),
					CertChain: []*x509.Certificate{
						{Raw: []byte{1}},
						{Raw: []byte{3}},
					},
					Bundle: []*x509.Certificate{
						{Raw: []byte{4}},
					},
					ExpiresAt: expiresAt,
				},
				Metadata: []string{"a:1", "b:2"},
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(test): failed to marshal key:",
		},
		{
			name: "fails to put svid",
			expectPutRequest: &svidstorev1.PutX509SVIDRequest{
				Svid: &svidstorev1.X509SVID{
					SpiffeID:   "spiffe://example.org/workload",
					PrivateKey: keyData,
					CertChain:  [][]byte{{1}, {3}},
					Bundle:     [][]byte{{4}},
					ExpiresAt:  expiresAt.Unix(),
				},
				FederatedBundles: map[string][]byte{
					"td1": {1},
					"td2": {2},
				},
			},
			x509SVID: &svidstore.X509SVID{
				FederatedBundles: federatedBundles,
				SVID:             svid,
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(test): oh no!",
		},
		{
			name: "missing svid",
			x509SVID: &svidstore.X509SVID{
				FederatedBundles: federatedBundles,
				Metadata:         []string{"a:1", "b:2"},
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "svidstore(test): missing SVID",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakePluginV1{
				t:                t,
				expectPutRequest: tt.expectPutRequest,
			}
			svidStore := makeFakeV1Plugin(fake)
			err := svidStore.PutX509SVID(context.Background(), tt.x509SVID)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)
		})
	}
}

func makeFakeV1Plugin(p *fakePluginV1) svidstore.SVIDStore {
	server := svidstorev1.SVIDStorePluginServer(p)

	plugin := new(svidstore.V1)
	plugintest.Load(p.t, catalog.MakeBuiltIn("test", server), plugin)
	return plugin
}

type fakePluginV1 struct {
	t *testing.T
	svidstorev1.UnimplementedSVIDStoreServer

	expectDeleteRequest *svidstorev1.DeleteX509SVIDRequest
	expectPutRequest    *svidstorev1.PutX509SVIDRequest
}

// Deletes stored SVID
func (p *fakePluginV1) DeleteX509SVID(_ context.Context, req *svidstorev1.DeleteX509SVIDRequest) (*svidstorev1.DeleteX509SVIDResponse, error) {
	if len(req.Metadata) == 0 {
		return nil, status.Error(codes.InvalidArgument, "oh no!")
	}
	spiretest.AssertProtoEqual(p.t, p.expectDeleteRequest, req)

	return &svidstorev1.DeleteX509SVIDResponse{}, nil
}

func (p *fakePluginV1) PutX509SVID(_ context.Context, req *svidstorev1.PutX509SVIDRequest) (*svidstorev1.PutX509SVIDResponse, error) {
	if len(req.Metadata) == 0 {
		return nil, status.Error(codes.InvalidArgument, "oh no!")
	}
	spiretest.AssertProtoEqual(p.t, p.expectPutRequest, req)

	return &svidstorev1.PutX509SVIDResponse{}, nil
}
