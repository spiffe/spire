package svidstore

import (
	"context"
	"crypto/x509"

	svidstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/svidstore/v1"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/pkg/common/x509util"
	"google.golang.org/grpc/codes"
)

type V1 struct {
	plugin.Facade

	svidstorev1.SVIDStorePluginClient
}

func (v1 *V1) DeleteX509SVID(ctx context.Context, metadata []string) error {
	_, err := v1.SVIDStorePluginClient.DeleteX509SVID(ctx, &svidstorev1.DeleteX509SVIDRequest{
		Metadata: metadata,
	})

	if err != nil {
		return v1.WrapErr(err)
	}

	return nil
}

func (v1 *V1) PutX509SVID(ctx context.Context, x509SVID *X509SVID) error {
	federatedBundles := make(map[string][]byte)
	for id, bundle := range x509SVID.FederatedBundles {
		federatedBundles[id] = x509util.DERFromCertificates(bundle)
	}

	if x509SVID.SVID == nil {
		return v1.Errorf(codes.InvalidArgument, "missing SVID")
	}

	keyData, err := x509.MarshalPKCS8PrivateKey(x509SVID.SVID.PrivateKey)
	if err != nil {
		return v1.Errorf(codes.InvalidArgument, "failed to marshal key: %v", err)
	}
	var svid *svidstorev1.X509SVID
	if x509SVID.SVID != nil {
		svid = &svidstorev1.X509SVID{
			SpiffeID:   x509SVID.SVID.SPIFFEID.String(),
			CertChain:  x509util.RawCertsFromCertificates(x509SVID.SVID.CertChain),
			PrivateKey: keyData,
			Bundle:     x509util.RawCertsFromCertificates(x509SVID.SVID.Bundle),
			ExpiresAt:  x509SVID.SVID.ExpiresAt.Unix(),
		}
	}

	req := &svidstorev1.PutX509SVIDRequest{
		Svid:             svid,
		Metadata:         x509SVID.Metadata,
		FederatedBundles: federatedBundles,
	}

	if _, err := v1.SVIDStorePluginClient.PutX509SVID(ctx, req); err != nil {
		return v1.WrapErr(err)
	}

	return nil
}
