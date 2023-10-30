package fakenotifier

import (
	"context"
	"testing"

	notifierv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/notifier/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/coretypes/bundle"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/plugintest"
)

type Config struct {
	OnNotifyBundleUpdated         func(*common.Bundle) error
	OnNotifyAndAdviseBundleLoaded func(*common.Bundle) error
}

func New(t *testing.T, config Config) notifier.Notifier {
	server := notifierv1.NotifierPluginServer(&fakeNotifier{config: config})

	v1 := new(notifier.V1)
	plugintest.Load(t, catalog.MakeBuiltIn("fake", server), v1)
	return v1
}

type fakeNotifier struct {
	notifierv1.UnimplementedNotifierServer

	config Config
}

func (n *fakeNotifier) Notify(_ context.Context, req *notifierv1.NotifyRequest) (*notifierv1.NotifyResponse, error) {
	var err error
	if event := req.GetBundleUpdated(); event != nil && n.config.OnNotifyBundleUpdated != nil {
		err = n.config.OnNotifyBundleUpdated(bundle.RequireToCommonFromPluginProto(event.Bundle))
	}
	return &notifierv1.NotifyResponse{}, err
}

func (n *fakeNotifier) NotifyAndAdvise(_ context.Context, req *notifierv1.NotifyAndAdviseRequest) (*notifierv1.NotifyAndAdviseResponse, error) {
	var err error
	if event := req.GetBundleLoaded(); event != nil && n.config.OnNotifyAndAdviseBundleLoaded != nil {
		err = n.config.OnNotifyAndAdviseBundleLoaded(bundle.RequireToCommonFromPluginProto(event.Bundle))
	}
	return &notifierv1.NotifyAndAdviseResponse{}, err
}

func NotifyBundleUpdatedWaiter(t *testing.T) (notifier.Notifier, <-chan *common.Bundle) {
	ch := make(chan *common.Bundle)
	return New(t, Config{
		OnNotifyBundleUpdated: func(bundle *common.Bundle) error {
			ch <- bundle
			return nil
		},
	}), ch
}
