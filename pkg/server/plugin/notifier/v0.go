package notifier

import (
	"context"

	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/proto/spire/common"
	notifierv0 "github.com/spiffe/spire/proto/spire/server/notifier/v0"
)

type V0 struct {
	plugin.Facade

	Plugin notifierv0.Notifier
}

func (v0 V0) NotifyAndAdviseBundleLoaded(ctx context.Context, bundle *common.Bundle) error {
	_, err := v0.Plugin.NotifyAndAdvise(ctx, &notifierv0.NotifyAndAdviseRequest{
		Event: &notifierv0.NotifyAndAdviseRequest_BundleLoaded{
			BundleLoaded: &notifierv0.BundleLoaded{
				Bundle: bundle,
			},
		},
	})
	return v0.WrapErr(err)
}

func (v0 V0) NotifyBundleUpdated(ctx context.Context, bundle *common.Bundle) error {
	_, err := v0.Plugin.Notify(ctx, &notifierv0.NotifyRequest{
		Event: &notifierv0.NotifyRequest_BundleUpdated{
			BundleUpdated: &notifierv0.BundleUpdated{
				Bundle: bundle,
			},
		},
	})
	return v0.WrapErr(err)
}
