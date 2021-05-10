package fakenotifier

import (
	"context"
	"testing"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/proto/spire/common"
	notifierv0 "github.com/spiffe/spire/proto/spire/plugin/server/notifier/v0"
	"github.com/spiffe/spire/test/plugintest"
)

type Config struct {
	OnNotifyBundleUpdated         func(*common.Bundle) error
	OnNotifyAndAdviseBundleLoaded func(*common.Bundle) error
}

func New(t *testing.T, config Config) notifier.Notifier {
	server := notifierv0.NotifierPluginServer(&fakeNotifer{config: config})

	v0 := new(notifier.V0)
	plugintest.Load(t, catalog.MakeBuiltIn("fake", server), v0)
	return v0
}

type fakeNotifer struct {
	notifierv0.UnimplementedNotifierServer

	config Config
}

func (n *fakeNotifer) Notify(ctx context.Context, req *notifierv0.NotifyRequest) (*notifierv0.NotifyResponse, error) {
	var err error
	if event := req.GetBundleUpdated(); event != nil && n.config.OnNotifyBundleUpdated != nil {
		err = n.config.OnNotifyBundleUpdated(event.Bundle)
	}
	return &notifierv0.NotifyResponse{}, err
}

func (n *fakeNotifer) NotifyAndAdvise(ctx context.Context, req *notifierv0.NotifyAndAdviseRequest) (*notifierv0.NotifyAndAdviseResponse, error) {
	var err error
	if event := req.GetBundleLoaded(); event != nil && n.config.OnNotifyAndAdviseBundleLoaded != nil {
		err = n.config.OnNotifyAndAdviseBundleLoaded(event.Bundle)
	}
	return &notifierv0.NotifyAndAdviseResponse{}, err
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
