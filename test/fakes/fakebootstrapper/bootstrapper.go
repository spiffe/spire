package fakebootstrapper

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/bootstrapper"
	"github.com/stretchr/testify/require"
)

type Bootstrapper struct {
	unpublishedBundles []*common.Bundle
	publishedBundles   []*common.Bundle
	next               []func(bootstrapper.PublishBundle_PluginStream) error
}

var _ bootstrapper.Plugin = (*Bootstrapper)(nil)

func New() *Bootstrapper {
	return &Bootstrapper{}
}

func (b *Bootstrapper) PublishBundle(stream bootstrapper.PublishBundle_PluginStream) error {
	if len(b.next) == 0 {
		return errors.New("fake bootstrapper not configured")
	}
	next := b.next[0]
	b.next = b.next[1:]
	return next(stream)
}

func (b *Bootstrapper) Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return &plugin.ConfigureResponse{}, nil
}

func (b *Bootstrapper) GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}

func (b *Bootstrapper) UnpublishedBundles() []*common.Bundle {
	return b.unpublishedBundles
}

func (b *Bootstrapper) PublishedBundles() []*common.Bundle {
	return b.publishedBundles
}

func (b *Bootstrapper) PublishNextBundle() func(t *testing.T) {
	return b.publishNextBundleAfterRetry(0)
}

func (b *Bootstrapper) PublishNextBundleAfterRetry(retries int) func(t *testing.T) {
	return b.publishNextBundleAfterRetry(retries)
}

func (b *Bootstrapper) publishNextBundleAfterRetry(retries int) func(t *testing.T) {
	done := make(chan struct{})
	b.next = append(b.next, func(stream bootstrapper.PublishBundle_PluginStream) error {
		defer close(done)
		var bundle *common.Bundle
		for i := 0; i <= retries; i++ {
			if bundle != nil {
				// bundle wasn't published
				b.unpublishedBundles = append(b.unpublishedBundles, bundle)
			}
			if err := stream.Send(&bootstrapper.PublishBundleResponse{}); err != nil {
				return err
			}
			req, err := stream.Recv()
			if err != nil {
				return err
			}
			if req.Bundle == nil {
				return errors.New("unsupported bundle")
			}
			bundle = req.Bundle
		}
		b.publishedBundles = append(b.publishedBundles, bundle)
		return nil
	})

	return func(t *testing.T) {
		timer := time.NewTimer(time.Minute)
		defer timer.Stop()

		select {
		case <-done:
		case <-timer.C:
			require.FailNow(t, "timed out waiting for PublishBundle to finish")
		}
	}
}
