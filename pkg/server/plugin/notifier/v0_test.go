package notifier_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/proto/spire/common"
	notifierv0 "github.com/spiffe/spire/proto/spire/plugin/server/notifier/v0"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestV0(t *testing.T) {
	bundle := &common.Bundle{TrustDomainId: "spiffe://example.org"}

	bundleLoaded := &notifierv0.NotifyAndAdviseRequest{
		Event: &notifierv0.NotifyAndAdviseRequest_BundleLoaded{
			BundleLoaded: &notifierv0.BundleLoaded{
				Bundle: bundle,
			},
		},
	}

	bundleUpdated := &notifierv0.NotifyRequest{
		Event: &notifierv0.NotifyRequest_BundleUpdated{
			BundleUpdated: &notifierv0.BundleUpdated{
				Bundle: bundle,
			},
		},
	}

	t.Run("notify and advise bundle loaded success", func(t *testing.T) {
		notifier := loadV0Plugin(t, bundleLoaded, nil)
		err := notifier.NotifyAndAdviseBundleLoaded(context.Background(), bundle)
		assert.NoError(t, err)
	})

	t.Run("notify and advise bundle loaded failure", func(t *testing.T) {
		notifier := loadV0Plugin(t, bundleLoaded, status.Error(codes.FailedPrecondition, "ohno"))
		err := notifier.NotifyAndAdviseBundleLoaded(context.Background(), bundle)
		spiretest.AssertGRPCStatus(t, err, codes.FailedPrecondition, "notifier(test): ohno")
	})

	t.Run("notify bundle updated success", func(t *testing.T) {
		notifier := loadV0Plugin(t, bundleUpdated, nil)
		err := notifier.NotifyBundleUpdated(context.Background(), bundle)
		assert.NoError(t, err)
	})

	t.Run("notify bundle updated failure", func(t *testing.T) {
		notifier := loadV0Plugin(t, bundleUpdated, status.Error(codes.FailedPrecondition, "ohno"))
		err := notifier.NotifyBundleUpdated(context.Background(), bundle)
		spiretest.AssertGRPCStatus(t, err, codes.FailedPrecondition, "notifier(test): ohno")
	})
}

func loadV0Plugin(t *testing.T, expectedReq proto.Message, err error) notifier.Notifier {
	server := notifierv0.NotifierPluginServer(&v0Plugin{
		expectedReq: expectedReq,
		err:         err,
	})

	v0 := new(notifier.V0)
	plugintest.Load(t, catalog.MakeBuiltIn("test", server), v0)
	return v0
}

type v0Plugin struct {
	notifierv0.UnimplementedNotifierServer
	expectedReq proto.Message
	err         error
}

func (v0 v0Plugin) Notify(ctx context.Context, req *notifierv0.NotifyRequest) (*notifierv0.NotifyResponse, error) {
	if diff := cmp.Diff(v0.expectedReq, req, protocmp.Transform()); diff != "" {
		return nil, fmt.Errorf("v0 shim issued an unexpected request:\n%s", diff)
	}
	return &notifierv0.NotifyResponse{}, v0.err
}

func (v0 v0Plugin) NotifyAndAdvise(ctx context.Context, req *notifierv0.NotifyAndAdviseRequest) (*notifierv0.NotifyAndAdviseResponse, error) {
	if diff := cmp.Diff(v0.expectedReq, req, protocmp.Transform()); diff != "" {
		return nil, fmt.Errorf("v0 shim issued an unexpected request:\n%s", diff)
	}
	return &notifierv0.NotifyAndAdviseResponse{}, v0.err
}
