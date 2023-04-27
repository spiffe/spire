package bundlepublisher

import (
	"context"

	bundlepublisherv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/bundlepublisher/v1"
	"github.com/spiffe/spire/pkg/common/coretypes/bundle"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
)

type V1 struct {
	plugin.Facade
	bundlepublisherv1.BundlePublisherPluginClient
}

func (v1 *V1) PublishBundle(ctx context.Context, b *common.Bundle) error {
	pluginBundle, err := bundle.ToPluginProtoFromCommon(b)
	if err != nil {
		return v1.Errorf(codes.InvalidArgument, "bundle is invalid: %v", err)
	}

	_, err = v1.BundlePublisherPluginClient.PublishBundle(ctx, &bundlepublisherv1.PublishBundleRequest{
		Bundle: pluginBundle,
	})
	return v1.WrapErr(err)
}
