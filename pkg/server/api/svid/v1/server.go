package svid

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/proto/spire-next/api/server/svid/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RegisterService registers the service on the gRPC server.
func RegisterService(s *grpc.Server, service Service) {
	svid.RegisterSVIDServer(s, server{service: service})
}

type server struct {
	service Service
}

func (s server) MintX509SVID(ctx context.Context, req *svid.MintX509SVIDRequest) (*svid.MintX509SVIDResponse, error) {
	log := rpccontext.Logger(ctx)

	if len(req.Csr) == 0 {
		log.Error("Request missing CSR")
		return nil, status.Errorf(codes.InvalidArgument, "request missing CSR")
	}

	csr, err := x509.ParseCertificateRequest(req.Csr)
	if err != nil {
		log.WithError(err).Error("Invalid CSR")
		return nil, status.Errorf(codes.InvalidArgument, "invalid CSR: %v", err)
	}

	x509Svid, err := s.service.MintX509SVID(ctx, csr, time.Duration(req.Ttl)*time.Second)
	if err != nil {
		return nil, err
	}

	return &svid.MintX509SVIDResponse{
		Svid: x509Svid.ToProto(),
	}, nil
}

func (s server) MintJWTSVID(context.Context, *svid.MintJWTSVIDRequest) (*svid.MintJWTSVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (s server) BatchNewX509SVID(ctx context.Context, req *svid.BatchNewX509SVIDRequest) (*svid.BatchNewX509SVIDResponse, error) {
	log := rpccontext.Logger(ctx)
	var logErrorOnce sync.Once

	if len(req.Params) == 0 {
		log.Error("Request missing parameters")
		return nil, status.Error(codes.InvalidArgument, "request missing parameters")
	}

	if err := rpccontext.RateLimit(ctx, len(req.Params)); err != nil {
		log.WithError(err).Error("Rejecting request due to certificate signing rate limiting")
		return nil, err
	}

	resp := &svid.BatchNewX509SVIDResponse{}

	// Parse and validate params
	var entries []*X509SVIDParams
	for _, svidParam := range req.Params {
		csr, err := parseNewX509SVIDParams(svidParam)
		switch {
		case err != nil:
			logErrorOnce.Do(func() {
				log.Error("Request has invalid arguments")
			})

			resp.Results = append(resp.Results, &svid.BatchNewX509SVIDResponse_Result{Status: api.CreateStatus(codes.InvalidArgument, err.Error())})
		default:
			entries = append(entries, &X509SVIDParams{
				EntryID: svidParam.EntryId,
				Csr:     csr,
			})
		}
	}

	bundles, err := s.service.BatchNewX509SVID(ctx, entries)
	if err != nil {
		return nil, err
	}

	for _, bundle := range bundles {
		resp.Results = append(resp.Results, &svid.BatchNewX509SVIDResponse_Result{
			Status: api.StatusFromError(bundle.Err),
			Bundle: x509SVIDToProto(bundle.Svid),
		})
	}

	return resp, nil
}

// parseNewX509SVIDParams validates and parse provided NewX509SVIDParams
func parseNewX509SVIDParams(svidParam *svid.NewX509SVIDParams) (*x509.CertificateRequest, error) {
	switch {
	case svidParam.EntryId == "":
		return nil, errors.New("invalid param: missing Entry ID")
	case len(svidParam.Csr) == 0:
		return nil, fmt.Errorf("invalid param %q: missing CSR", svidParam.EntryId)
	}

	csr, err := x509.ParseCertificateRequest(svidParam.Csr)
	if err != nil {
		return nil, fmt.Errorf("invalid param %q: invalid CSR: %v", svidParam.EntryId, err)
	}

	return csr, nil
}

func (s server) NewJWTSVID(context.Context, *svid.NewJWTSVIDRequest) (*svid.NewJWTSVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (s server) NewDownstreamX509CA(context.Context, *svid.NewDownstreamX509CARequest) (*svid.NewDownstreamX509CAResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func x509SVIDToProto(s *api.X509SVID) *types.X509SVID {
	if s == nil {
		return nil
	}

	return s.ToProto()
}
