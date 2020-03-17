package upstreamauthority

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/spiffe/spire/pkg/server/plugin/upstreamca"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type wrapper struct {
	upstreamCA upstreamca.UpstreamCA
}

// Wrap produces a conforming UpstreamAuthority by wrapping an UpstreamCA. The PublishJWTKey method is not implemented and returns a codes.Unimplemented status.
func Wrap(upstreamCA upstreamca.UpstreamCA) *wrapper { // nolint
	return &wrapper{upstreamCA: upstreamCA}
}

// MintX509CA mints an X509CA by forwarding the request to the wrapped UpstreamCA's SubmitCSR method
func (w *wrapper) MintX509CA(ctx context.Context, request *MintX509CARequest) (*MintX509CAResponse, error) {
	// Create a SubmitCSRRequest from MintX509CARequest
	req := &upstreamca.SubmitCSRRequest{
		Csr:          request.Csr,
		PreferredTtl: request.PreferredTtl,
	}

	// Call upstreamCA SubmitCSR
	resp, err := w.upstreamCA.SubmitCSR(ctx, req)
	if err != nil {
		return nil, makeError(codes.Internal, "unable to submit csr: %v", err)
	}

	// Creates an array of []byte from response CertChain
	caChain, err := parseCertificates(resp.SignedCertificate.CertChain)
	if err != nil {
		return nil, makeError(codes.Internal, "unable to parse cert chain: %v", err)
	}

	// Creates an array of []byte from response Bundle
	roots, err := parseCertificates(resp.SignedCertificate.Bundle)
	if err != nil {
		return nil, makeError(codes.Internal, "unable to parse bundle: %v", err)
	}

	return &MintX509CAResponse{
		X509CaChain:       caChain,
		UpstreamX509Roots: roots,
	}, nil
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

// PublishJWTKey is not implemented by the wrapper and returns a codes.Unimplemented status
func (w *wrapper) PublishJWTKey(ctx context.Context, request *PublishJWTKeyRequest) (*PublishJWTKeyResponse, error) {
	return nil, makeError(codes.Unimplemented, "publishing upstream is unsupported")
}

func makeError(code codes.Code, format string, args ...interface{}) error {
	return status.Errorf(code, "upstreamauthority-wrapper: "+format, args...)
}

func (w *wrapper) Name() string {
	return fmt.Sprintf("%T wrapper", w.upstreamCA)
}
