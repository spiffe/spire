package bundlepublisher_test

import (
	"context"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	bundlepublisherv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/bundlepublisher/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/bundlepublisher"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestV1Publish(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	commonBundle := &common.Bundle{
		TrustDomainId: td.IDString(),
		RootCas:       []*common.Certificate{{DerBytes: testca.New(t, td).X509Authorities()[0].Raw}},
	}

	for _, tt := range []struct {
		test          string
		bundle        *common.Bundle
		pluginErr     error
		expectCode    codes.Code
		expectMessage string
	}{
		{
			test:   "publish bundle success",
			bundle: commonBundle,
		},
		{
			test:          "plugin error",
			bundle:        commonBundle,
			pluginErr:     status.Error(codes.Internal, "oh no"),
			expectCode:    codes.Internal,
			expectMessage: "bundlepublisher(test): oh no",
		},
		{
			test:          "publish bundle with invalid bundle",
			bundle:        &common.Bundle{},
			expectCode:    codes.InvalidArgument,
			expectMessage: "bundlepublisher(test): bundle is invalid: trust domain is missing",
		},
	} {
		tt := tt
		t.Run(tt.test, func(t *testing.T) {
			bundlepublisher := loadV1Plugin(t, &fakeV1Plugin{err: tt.pluginErr})
			err := bundlepublisher.PublishBundle(context.Background(), tt.bundle)
			if tt.expectCode != codes.OK {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMessage)
				return
			}
			require.NoError(t, err)
		})
	}
}

func loadV1Plugin(t *testing.T, plugin *fakeV1Plugin) bundlepublisher.BundlePublisher {
	server := bundlepublisherv1.BundlePublisherPluginServer(plugin)
	cc := new(bundlepublisher.V1)
	plugintest.Load(t, catalog.MakeBuiltIn("test", server), cc)
	return cc
}

type fakeV1Plugin struct {
	bundlepublisherv1.UnimplementedBundlePublisherServer
	err error
}

func (p *fakeV1Plugin) PublishBundle(context.Context, *bundlepublisherv1.PublishBundleRequest) (*bundlepublisherv1.PublishBundleResponse, error) {
	return &bundlepublisherv1.PublishBundleResponse{}, p.err
}
