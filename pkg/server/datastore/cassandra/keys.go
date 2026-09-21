package cassandra

import (
	"context"
	"crypto/x509"

	datastorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/datastore/v1alpha1"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Effectively a 1:1 copy from pkg/server/datastore/sqlstore/sqlstore.go:1451
func (p *Plugin) TaintX509CA(ctx context.Context, req *datastorev1.TaintX509CARequest) (*datastorev1.TaintX509CAResponse, error) {
	bundleResp, err := p.FetchBundle(ctx, &datastorev1.FetchBundleRequest{TrustDomain: req.TrustDomain})
	if err != nil {
		return nil, err
	}
	if bundleResp.Bundle == nil {
		return nil, status.Error(codes.NotFound, NotFoundErr.Error())
	}

	commonBundle, err := dataToBundle(bundleResp.Bundle.Data)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse bundle data: %v", err)
	}

	found := false
	for _, eachRootCA := range commonBundle.RootCas {
		x509CA, err := x509.ParseCertificate(eachRootCA.DerBytes)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to parse rootCA: %v", err)
		}

		caSubjectKeyID := x509util.SubjectKeyIDToString(x509CA.SubjectKeyId)
		if req.KeyId != caSubjectKeyID {
			continue
		}

		if eachRootCA.TaintedKey {
			return nil, status.Errorf(codes.InvalidArgument, "root CA is already tainted")
		}

		found = true
		eachRootCA.TaintedKey = true
	}

	if !found {
		return nil, status.Error(codes.NotFound, "no ca found with provided subject key ID")
	}

	commonBundle.SequenceNumber++

	dataBundle, err := bundleToModel(commonBundle)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to serialize bundle data: %v", err)
	}
	_, err = p.updateBundle(ctx, &datastorev1.UpdateBundleRequest{
		Bundle: dataBundle,
	})
	return &datastorev1.TaintX509CAResponse{}, err
}

// Effectively a 1:1 copy from pkg/server/datastore/sqlstore/sqlstore.go:1488
func (p *Plugin) RevokeX509CA(ctx context.Context, req *datastorev1.RevokeX509CARequest) (*datastorev1.RevokeX509CAResponse, error) {
	bundleResp, err := p.FetchBundle(ctx, &datastorev1.FetchBundleRequest{
		TrustDomain: req.TrustDomain,
	})
	if err != nil {
		return nil, err
	}
	if bundleResp.GetBundle() == nil {
		return nil, status.Error(codes.NotFound, NotFoundErr.Error())
	}

	bundle, err := dataToBundle(bundleResp.Bundle.Data)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse bundle data: %v", err)
	}

	keyFound := false
	var rootCAs []*common.Certificate
	for _, ca := range bundle.RootCas {
		cert, err := x509.ParseCertificate(ca.DerBytes)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to parse root CA: %v", err)
		}

		caSubjectKeyID := x509util.SubjectKeyIDToString(cert.SubjectKeyId)
		if req.KeyId == caSubjectKeyID {
			if !ca.TaintedKey {
				return nil, status.Error(codes.InvalidArgument, "it is not possible to revoke an untainted root CA")
			}
			keyFound = true
			continue
		}

		rootCAs = append(rootCAs, ca)
	}

	if !keyFound {
		return nil, status.Error(codes.NotFound, "no root CA found with provided subject key ID")
	}

	bundle.RootCas = rootCAs
	bundle.SequenceNumber++

	modelBundle, err := bundleToModel(bundle)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to serialize bundle data: %v", err)
	}

	if _, err := p.updateBundle(ctx, &datastorev1.UpdateBundleRequest{
		Bundle: modelBundle,
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update bundle: %v", err)
	}

	return &datastorev1.RevokeX509CAResponse{}, nil
}

// Effectively a 1:1 copy from pkg/server/datastore/sqlstore/sqlstore.go:1527
func (p *Plugin) TaintJWTKey(ctx context.Context, req *datastorev1.TaintJWTKeyRequest) (*datastorev1.TaintJWTKeyResponse, error) {
	bundleResp, err := p.FetchBundle(ctx, &datastorev1.FetchBundleRequest{TrustDomain: req.GetTrustDomain()})
	if err != nil {
		return nil, err
	}
	if bundleResp.GetBundle() == nil {
		return nil, status.Error(codes.NotFound, NotFoundErr.Error())
	}

	bundle, err := dataToBundle(bundleResp.Bundle.Data)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse bundle data: %v", err)
	}

	var taintedKey *common.PublicKey
	for _, jwtKey := range bundle.JwtSigningKeys {
		if jwtKey.Kid != req.AuthorityId {
			continue
		}

		if jwtKey.TaintedKey {
			return nil, status.Error(codes.InvalidArgument, "key is already tainted")
		}

		// Check if a JWT Key with the provided keyID was already
		// tainted in this loop. This is purely defensive since we do not
		// allow to have repeated key IDs.
		if taintedKey != nil {
			return nil, status.Error(codes.Internal, "another JWT Key found with the same KeyID")
		}
		taintedKey = jwtKey
		jwtKey.TaintedKey = true
	}

	if taintedKey == nil {
		return nil, status.Error(codes.NotFound, "no JWT Key found with provided key ID")
	}

	bundle.SequenceNumber++

	modelBundle, err := bundleToModel(bundle)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to serialize bundle data: %v", err)
	}
	if _, err := p.updateBundle(ctx, &datastorev1.UpdateBundleRequest{
		Bundle: modelBundle,
	}); err != nil {
		return nil, err
	}

	return &datastorev1.TaintJWTKeyResponse{Key: &datastorev1.PublicKey{
		Kid:        taintedKey.Kid,
		TaintedKey: taintedKey.TaintedKey,
		NotAfter:   taintedKey.NotAfter,
		PkixBytes:  taintedKey.PkixBytes,
	}}, nil
}

// Effectively a 1:1 copy from pkg/server/datastore/sqlstore/sqlstore.go:1565
func (p *Plugin) RevokeJWTKey(ctx context.Context, req *datastorev1.RevokeJWTKeyRequest) (*datastorev1.RevokeJWTKeyResponse, error) {
	bundleResp, err := p.FetchBundle(ctx, &datastorev1.FetchBundleRequest{TrustDomain: req.GetTrustDomain()})
	if err != nil {
		return nil, err
	}
	if bundleResp.GetBundle() == nil {
		return nil, status.Error(codes.NotFound, NotFoundErr.Error())
	}

	bundle, err := dataToBundle(bundleResp.Bundle.Data)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse bundle data: %v", err)
	}

	var publicKeys []*common.PublicKey
	var revokedKey *common.PublicKey
	for _, key := range bundle.JwtSigningKeys {
		if key.Kid == req.AuthorityId {
			// Check if a JWT Key with the provided keyID was already
			// found in this loop. This is purely defensive since we do not
			// allow to have repeated key IDs.
			if revokedKey != nil {
				return nil, status.Error(codes.Internal, "another key found with the same KeyID")
			}

			if !key.TaintedKey {
				return nil, status.Error(codes.InvalidArgument, "it is not possible to revoke an untainted key")
			}

			revokedKey = key
			continue
		}
		publicKeys = append(publicKeys, key)
	}
	bundle.JwtSigningKeys = publicKeys

	if revokedKey == nil {
		return nil, status.Error(codes.NotFound, "no JWT Key found with provided key ID")
	}

	bundle.SequenceNumber++
	modelBundle, err := bundleToModel(bundle)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to serialize bundle data: %v", err)
	}
	if _, err := p.updateBundle(ctx, &datastorev1.UpdateBundleRequest{
		Bundle: modelBundle,
	}); err != nil {
		return nil, err
	}

	return &datastorev1.RevokeJWTKeyResponse{Key: &datastorev1.PublicKey{
		Kid:        revokedKey.Kid,
		TaintedKey: revokedKey.TaintedKey,
		NotAfter:   revokedKey.NotAfter,
		PkixBytes:  revokedKey.PkixBytes,
	}}, nil
}
