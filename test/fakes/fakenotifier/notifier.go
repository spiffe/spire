package fakenotifier

import (
	"context"

	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/proto/spire/common/plugin"
)

type Config struct {
	OnNotify          func(*notifier.NotifyRequest) (*notifier.NotifyResponse, error)
	OnNotifyAndAdvise func(*notifier.NotifyAndAdviseRequest) (*notifier.NotifyAndAdviseResponse, error)
}

type Notifier struct {
	config Config
}

func New(config Config) *Notifier {
	return &Notifier{
		config: config,
	}
}

func (n *Notifier) Notify(ctx context.Context, req *notifier.NotifyRequest) (*notifier.NotifyResponse, error) {
	if n.config.OnNotify != nil {
		return n.config.OnNotify(req)
	}
	return &notifier.NotifyResponse{}, nil
}

func (n *Notifier) NotifyAndAdvise(ctx context.Context, req *notifier.NotifyAndAdviseRequest) (*notifier.NotifyAndAdviseResponse, error) {
	if n.config.OnNotifyAndAdvise != nil {
		return n.config.OnNotifyAndAdvise(req)
	}
	return &notifier.NotifyAndAdviseResponse{}, nil
}

func (n *Notifier) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return &plugin.ConfigureResponse{}, nil
}

func (n *Notifier) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}

func NotifyWaiter() (*Notifier, <-chan *notifier.NotifyRequest) {
	ch := make(chan *notifier.NotifyRequest)
	return New(Config{
		OnNotify: SendOnNotify(ch),
	}), ch
}

func SendOnNotify(ch chan<- *notifier.NotifyRequest) func(req *notifier.NotifyRequest) (*notifier.NotifyResponse, error) {
	return func(req *notifier.NotifyRequest) (*notifier.NotifyResponse, error) {
		ch <- req
		return &notifier.NotifyResponse{}, nil
	}
}
