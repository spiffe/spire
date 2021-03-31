package svidstore

import (
	"context"
	"crypto/x509"

	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/pkg/common/x509util"
	svidstorev0 "github.com/spiffe/spire/proto/spire/plugin/agent/svidstore/v0"
	"google.golang.org/grpc/codes"
)

type V0 struct {
	plugin.Facade

	Plugin svidstorev0.SVIDStore
}

func (v0 V0) DeleteX509SVID(ctx context.Context, secretData []string) error {
	_, err := v0.Plugin.DeleteX509SVID(ctx, &svidstorev0.DeleteX509SVIDRequest{
		SecretData: secretData,
	})

	if err != nil {
		return v0.WrapErr(err)
	}

	return nil
}

func (v0 V0) PutX509SVID(ctx context.Context, x509SVID *X509SVID) error {
	federatedBundles := make(map[string][]byte)
	for id, bundle := range x509SVID.FederatedBundles {
		federatedBundles[id] = x509util.DERFromCertificates(bundle)
	}

	keyData, err := x509.MarshalPKCS8PrivateKey(x509SVID.SVID.PrivateKey)
	if err != nil {
		return v0.Errorf(codes.Internal, "failed to marshal key: %v", err)
	}
	var svid *svidstorev0.X509SVID
	if x509SVID.SVID != nil {
		svid = &svidstorev0.X509SVID{
			SpiffeID:   x509SVID.SVID.SpiffeID.String(),
			CertChain:  x509util.RawCertsFromCertificates(x509SVID.SVID.CertChain),
			PrivateKey: keyData,
			Bundle:     x509util.RawCertsFromCertificates(x509SVID.SVID.Bundle),
			ExpiresAt:  x509SVID.SVID.ExpiresAt.Unix(),
		}
	}

	req := &svidstorev0.PutX509SVIDRequest{
		Svid:             svid,
		SecretData:       x509SVID.SecretsData,
		FederatedBundles: federatedBundles,
	}

	if _, err := v0.Plugin.PutX509SVID(ctx, req); err != nil {
		return v0.WrapErr(err)
	}

	return nil
}
