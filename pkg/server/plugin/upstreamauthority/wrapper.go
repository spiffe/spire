package upstreamauthority

import (
	"context"
	"crypto/x509"

	"github.com/spiffe/spire/pkg/server/plugin/upstreamca"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	wrapperErr = errs.Class("upstreamauthority-wrapper")
)

type wrapper struct {
	upstreamCA upstreamca.UpstreamCA
}

// Wrap creates a wrapper for UpstreamCA interface that satisfies the UpstreamAuthority interface
func Wrap(upstreamCA upstreamca.UpstreamCA) UpstreamAuthority {
	return &wrapper{upstreamCA: upstreamCA}
}

// MintX509CA pass MinMintX509CA request to UpstreamCA SubmitCSR RPC, parse SubmitCSRResponse into MintX509CAResponse
func (w *wrapper) MintX509CA(ctx context.Context, request *MintX509CARequest) (*MintX509CAResponse, error) {
	// Create a SubmitCSRRequest from MintX509CARequest
	req := &upstreamca.SubmitCSRRequest{
		Csr:          request.Csr,
		PreferredTtl: request.PreferredTtl,
	}

	// Call upstreamCA SubmitCSR
	resp, err := w.upstreamCA.SubmitCSR(ctx, req)
	if err != nil {
		return nil, err
	}

	// Creates an array of []byte from response CertChain
	caChain, err := parseCertificates(resp.SignedCertificate.CertChain)
	if err != nil {
		return nil, wrapperErr.New("unable to parse cert chain: %v", err)
	}

	// Creates an array of []byte from response Bundle
	roots, err := parseCertificates(resp.SignedCertificate.Bundle)
	if err != nil {
		return nil, wrapperErr.New("unable to parse bundle: %v", err)
	}

	return &MintX509CAResponse{
		X509CaChain:       caChain,
		UpstreamX509Roots: roots,
	}, nil
}

// PublishJWTKey it is not implemented for wrapper
func (w *wrapper) PublishJWTKey(ctx context.Context, request *PublishJWTKeyRequest) (*PublishJWTKeyResponse, error) {
	return nil, status.Error(codes.Unimplemented, "publishing upstream is unsupported")
}

// PublishX509CA it is not implemented for wrapper
func (w *wrapper) PublishX509CA(ctx context.Context, request *PublishX509CARequest) (*PublishX509CAResponse, error) {
	return nil, status.Error(codes.Unimplemented, "publishing upstream is unsupported")
}

// parseCertificates parse certificates and return an array with each certificate raw
func parseCertificates(rawCerts []byte) ([][]byte, error) {
	var certificates [][]byte
	certChain, err := x509.ParseCertificates(rawCerts)
	if err != nil {
		return nil, err
	}

	for _, cert := range certChain {
		certificates = append(certificates, cert.Raw)
	}

	return certificates, nil
}
