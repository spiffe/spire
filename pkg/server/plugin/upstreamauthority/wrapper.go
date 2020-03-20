package upstreamauthority

import (
	"context"
	"crypto/x509"
	"errors"
	"io"

	"google.golang.org/grpc/metadata"

	"github.com/spiffe/spire/proto/spire/server/upstreamauthority"

	"github.com/spiffe/spire/pkg/server/plugin/upstreamca"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type wrapper struct {
	upstreamCA upstreamca.UpstreamCA
}

// Wrap produces a conforming UpstreamAuthority by wrapping an UpstreamCA. The PublishJWTKey method is not implemented and returns a codes.Unimplemented status.
func Wrap(upstreamCA upstreamca.UpstreamCA) UpstreamAuthority {
	return &wrapper{upstreamCA: upstreamCA}
}

// MintX509CA mints an X509CA by forwarding the request to the wrapped UpstreamCA's SubmitCSR method
func (w *wrapper) MintX509CA(ctx context.Context, request *MintX509CARequest) (UpstreamAuthority_MintX509CAClient, error) {
	// Create a SubmitCSRRequest from MintX509CARequest
	req := &upstreamca.SubmitCSRRequest{
		Csr:          request.Csr,
		PreferredTtl: request.PreferredTtl,
	}

	// Call upstreamCA SubmitCSR
	resp, err := w.upstreamCA.SubmitCSR(ctx, req)
	if err != nil {
		return &mintX509CAClientStream{
			ctx: ctx,
			err: makeError(codes.Internal, "unable to submit csr: %v", err),
		}, nil
	}

	// Creates an array of []byte from response CertChain
	caChain, err := parseCertificates(resp.SignedCertificate.CertChain)
	if err != nil {
		return &mintX509CAClientStream{
			ctx: ctx,
			err: makeError(codes.Internal, "unable to parse cert chain: %v", err),
		}, nil
	}

	// Creates an array of []byte from response Bundle
	roots, err := parseCertificates(resp.SignedCertificate.Bundle)
	if err != nil {
		return &mintX509CAClientStream{
			ctx: ctx,
			err: makeError(codes.Internal, "unable to parse bundle: %v", err),
		}, nil
	}

	return &mintX509CAClientStream{
		ctx: ctx,
		resp: &upstreamauthority.MintX509CAResponse{
			X509CaChain:       caChain,
			UpstreamX509Roots: roots,
		},
		err: nil,
	}, nil
}

// PublishJWTKey is not implemented by the wrapper and returns a codes.Unimplemented status
func (w *wrapper) PublishJWTKey(ctx context.Context, request *PublishJWTKeyRequest) (UpstreamAuthority_PublishJWTKeyClient, error) {
	return nil, makeError(codes.Unimplemented, "publishing upstream is unsupported")
}

type mintX509CAClientStream struct {
	ctx  context.Context
	resp *MintX509CAResponse

	err error
}

func (s *mintX509CAClientStream) Header() (metadata.MD, error) {
	return nil, errors.New("not implemented by wrapper")
}

func (s *mintX509CAClientStream) Trailer() metadata.MD {
	return nil
}

func (s *mintX509CAClientStream) Context() context.Context {
	return s.ctx
}

func (s *mintX509CAClientStream) Recv() (*upstreamauthority.MintX509CAResponse, error) {
	if s.err != nil {
		return nil, s.err
	}

	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	resp := s.resp
	s.resp = nil
	if resp == nil {
		return nil, io.EOF
	}
	return resp, nil
}

func (s *mintX509CAClientStream) RecvMsg(interface{}) error {
	return errors.New("not implemented by wrapper")
}

func (s *mintX509CAClientStream) SendMsg(interface{}) error {
	return errors.New("not implemented by wrapper")
}

func (s *mintX509CAClientStream) CloseSend() error {
	return nil
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

func makeError(code codes.Code, format string, args ...interface{}) error {
	return status.Errorf(code, "upstreamauthority-wrapper: "+format, args...)
}
