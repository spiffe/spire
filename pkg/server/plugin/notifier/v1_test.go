package notifier_test

import (
	"context"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	notifierv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/notifier/v1"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestV1(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	publicKey := testkey.MustEC256().Public()
	pkixBytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	derBytes := testca.New(t, td).X509Authorities()[0].Raw
	commonBundle := &common.Bundle{
		TrustDomainId:  td.IDString(),
		RootCas:        []*common.Certificate{{DerBytes: derBytes}},
		JwtSigningKeys: []*common.PublicKey{{Kid: "KEYID", PkixBytes: pkixBytes, NotAfter: 4321}},
		RefreshHint:    1234,
		SequenceNumber: 42,
	}

	pluginBundle := &types.Bundle{
		TrustDomain: "example.org",
		X509Authorities: []*types.X509Certificate{
			{
				Asn1: derBytes,
			},
		},
		JwtAuthorities: []*types.JWTKey{
			{
				KeyId:     "KEYID",
				PublicKey: pkixBytes,
				ExpiresAt: 4321,
			},
		},
		RefreshHint:    1234,
		SequenceNumber: 42,
	}

	bundleLoaded := &notifierv1.NotifyAndAdviseRequest{
		Event: &notifierv1.NotifyAndAdviseRequest_BundleLoaded{
			BundleLoaded: &notifierv1.BundleLoaded{
				Bundle: pluginBundle,
			},
		},
	}

	bundleUpdated := &notifierv1.NotifyRequest{
		Event: &notifierv1.NotifyRequest_BundleUpdated{
			BundleUpdated: &notifierv1.BundleUpdated{
				Bundle: pluginBundle,
			},
		},
	}

	t.Run("notify and advise bundle loaded success", func(t *testing.T) {
		notifier := loadV1Plugin(t, bundleLoaded, nil)
		err := notifier.NotifyAndAdviseBundleLoaded(context.Background(), commonBundle)
		assert.NoError(t, err)
	})

	t.Run("notify and advise bundle loaded failure", func(t *testing.T) {
		notifier := loadV1Plugin(t, bundleLoaded, status.Error(codes.FailedPrecondition, "ohno"))
		err := notifier.NotifyAndAdviseBundleLoaded(context.Background(), commonBundle)
		spiretest.AssertGRPCStatus(t, err, codes.FailedPrecondition, "notifier(test): ohno")
	})

	t.Run("notify and advise bundle loaded with invalid bundle", func(t *testing.T) {
		notifier := loadV1Plugin(t, bundleUpdated, nil)
		err := notifier.NotifyAndAdviseBundleLoaded(context.Background(), &common.Bundle{})
		spiretest.AssertGRPCStatus(t, err, codes.InvalidArgument, "notifier(test): bundle is invalid: trust domain is missing")
	})

	t.Run("notify bundle updated success", func(t *testing.T) {
		notifier := loadV1Plugin(t, bundleUpdated, nil)
		err := notifier.NotifyBundleUpdated(context.Background(), commonBundle)
		assert.NoError(t, err)
	})

	t.Run("notify bundle updated failure", func(t *testing.T) {
		notifier := loadV1Plugin(t, bundleUpdated, status.Error(codes.FailedPrecondition, "ohno"))
		err := notifier.NotifyBundleUpdated(context.Background(), commonBundle)
		spiretest.AssertGRPCStatus(t, err, codes.FailedPrecondition, "notifier(test): ohno")
	})

	t.Run("notify bundle updated with invalid bundle", func(t *testing.T) {
		notifier := loadV1Plugin(t, bundleUpdated, nil)
		err := notifier.NotifyBundleUpdated(context.Background(), &common.Bundle{})
		spiretest.AssertGRPCStatus(t, err, codes.InvalidArgument, "notifier(test): bundle is invalid: trust domain is missing")
	})
}

func loadV1Plugin(t *testing.T, expectedReq proto.Message, err error) notifier.Notifier {
	server := notifierv1.NotifierPluginServer(&v1Plugin{
		expectedReq: expectedReq,
		err:         err,
	})

	v1 := new(notifier.V1)
	plugintest.Load(t, catalog.MakeBuiltIn("test", server), v1)
	return v1
}

type v1Plugin struct {
	notifierv1.UnimplementedNotifierServer
	expectedReq proto.Message
	err         error
}

func (v1 v1Plugin) Notify(_ context.Context, req *notifierv1.NotifyRequest) (*notifierv1.NotifyResponse, error) {
	if diff := cmp.Diff(v1.expectedReq, req, protocmp.Transform()); diff != "" {
		return nil, fmt.Errorf("v1 shim issued an unexpected request:\n%s", diff)
	}
	return &notifierv1.NotifyResponse{}, v1.err
}

func (v1 v1Plugin) NotifyAndAdvise(_ context.Context, req *notifierv1.NotifyAndAdviseRequest) (*notifierv1.NotifyAndAdviseResponse, error) {
	if diff := cmp.Diff(v1.expectedReq, req, protocmp.Transform()); diff != "" {
		return nil, fmt.Errorf("v1 shim issued an unexpected request:\n%s", diff)
	}
	return &notifierv1.NotifyAndAdviseResponse{}, v1.err
}
