package svidstore

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/pkg/common/x509util"
	svidstorev1 "github.com/spiffe/spire/proto/spire/agent/svidstore/v1"
)

type V1 struct {
	plugin.Facade

	Plugin svidstorev1.SVIDStore
}

func (v1 V1) DeleteX509SVID(ctx context.Context, secretData []string) error {
	_, err := v1.Plugin.DeleteX509SVID(ctx, &svidstorev1.DeleteX509SVIDRequest{
		SecretData: secretData,
	})

	if err != nil {
		return v1.WrapErr(err)
	}

	return nil
}

func (v1 V1) PutX509SVID(ctx context.Context, x509SVID *X509SVID) error {
	federatedBundles := make(map[string][]byte)
	for id, bundle := range x509SVID.FederatedBundles {
		federatedBundles[id] = x509util.DERFromCertificates(bundle)
	}

	keyData, err := x509.MarshalPKCS8PrivateKey(x509SVID.Svid.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %v", err)
	}
	var svid *svidstorev1.X509SVID
	if x509SVID.Svid != nil {
		svid = &svidstorev1.X509SVID{
			SpiffeID:   x509SVID.Svid.SpiffeID.String(),
			CertChain:  x509util.RawCertsFromCertificates(x509SVID.Svid.CertChain),
			PrivateKey: keyData,
			Bundle:     x509util.RawCertsFromCertificates(x509SVID.Svid.Bundle),
			ExpiresAt:  x509SVID.Svid.ExpiresAt.Unix(),
		}
	}

	req := &svidstorev1.PutX509SVIDRequest{
		Svid:             svid,
		SecretData:       x509SVID.SecretsData,
		FederatedBundles: federatedBundles,
	}

	if _, err := v1.Plugin.PutX509SVID(ctx, req); err != nil {
		return v1.WrapErr(err)
	}

	return nil
}
