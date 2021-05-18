package notifier

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	notifierv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/notifier/v1"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
)

type V1 struct {
	plugin.Facade
	notifierv1.NotifierPluginClient
}

func (v1 *V1) NotifyAndAdviseBundleLoaded(ctx context.Context, bundle *common.Bundle) error {
	pluginBundle, err := bundleFromCommonProto(bundle)
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

func (v1 *V1) NotifyBundleUpdated(ctx context.Context, bundle *common.Bundle) error {
	pluginBundle, err := bundleFromCommonProto(bundle)
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

func bundleFromCommonProto(b *common.Bundle) (*types.Bundle, error) {
	td, err := spiffeid.TrustDomainFromString(b.TrustDomainId)
	if err != nil {
		return nil, err
	}
	return &types.Bundle{
		TrustDomain:     td.String(),
		RefreshHint:     b.RefreshHint,
		SequenceNumber:  0,
		X509Authorities: certificatesToProto(b.RootCas),
		JwtAuthorities:  publicKeysToProto(b.JwtSigningKeys),
	}, nil
}

func certificatesToProto(rootCas []*common.Certificate) []*types.X509Certificate {
	var x509Authorities []*types.X509Certificate
	for _, rootCA := range rootCas {
		x509Authorities = append(x509Authorities, &types.X509Certificate{
			Asn1: rootCA.DerBytes,
		})
	}

	return x509Authorities
}
func publicKeysToProto(keys []*common.PublicKey) []*types.JWTKey {
	var jwtAuthorities []*types.JWTKey
	for _, key := range keys {
		jwtAuthorities = append(jwtAuthorities, &types.JWTKey{
			PublicKey: key.PkixBytes,
			KeyId:     key.Kid,
			ExpiresAt: key.NotAfter,
		})
	}
	return jwtAuthorities
}
