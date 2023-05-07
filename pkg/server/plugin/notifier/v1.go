package notifier

import (
	"context"

	notifierv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/notifier/v1"
	"github.com/spiffe/spire/pkg/common/coretypes/bundle"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
)

type V1 struct {
	plugin.Facade
	notifierv1.NotifierPluginClient
}

func (v1 *V1) NotifyAndAdviseBundleLoaded(ctx context.Context, b *common.Bundle) error {
	pluginBundle, err := bundle.ToPluginProtoFromCommon(b)
	if err != nil {
		return v1.Errorf(codes.InvalidArgument, "bundle is invalid: %v", err)
	}
	_, err = v1.NotifierPluginClient.NotifyAndAdvise(ctx, &notifierv1.NotifyAndAdviseRequest{
		Event: &notifierv1.NotifyAndAdviseRequest_BundleLoaded{
			BundleLoaded: &notifierv1.BundleLoaded{
				Bundle: pluginBundle,
			},
		},
	})
	return v1.WrapErr(err)
}

func (v1 *V1) NotifyBundleUpdated(ctx context.Context, b *common.Bundle) error {
	pluginBundle, err := bundle.ToPluginProtoFromCommon(b)
	if err != nil {
		return v1.Errorf(codes.InvalidArgument, "bundle is invalid: %v", err)
	}
	_, err = v1.NotifierPluginClient.Notify(ctx, &notifierv1.NotifyRequest{
		Event: &notifierv1.NotifyRequest_BundleUpdated{
			BundleUpdated: &notifierv1.BundleUpdated{
				Bundle: pluginBundle,
			},
		},
	})
	return v1.WrapErr(err)
}
