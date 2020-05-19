package svid

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
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
		Svid: parseX509SVID(x509Svid),
	}, nil
}

func (s server) MintJWTSVID(context.Context, *svid.MintJWTSVIDRequest) (*svid.MintJWTSVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (s server) BatchNewX509SVID(ctx context.Context, req *svid.BatchNewX509SVIDRequest) (*svid.BatchNewX509SVIDResponse, error) {
	log := rpccontext.Logger(ctx)

	if err := rpccontext.RateLimit(ctx, len(req.Params)); err != nil {
		log.WithError(err).Error("Rejecting request due to certificate signing rate limiting")
		return nil, status.Error(codes.ResourceExhausted, err.Error())
	}

	if len(req.Params) == 0 {
		log.Error("Request missing parameters")
		return nil, status.Error(codes.InvalidArgument, "request missing parameters")
	}

	resp := &svid.BatchNewX509SVIDResponse{
		Results: []*svid.BatchNewX509SVIDResponse_Result{},
	}

	// Parse and validate params
	var entries []*BatchNewX509SVIDRequest
	for _, svidParam := range req.Params {
		csr, status := parseNewX509SVIDParams(svidParam, log)
		switch {
		case status != nil:
			resp.Results = append(resp.Results, &svid.BatchNewX509SVIDResponse_Result{Status: status})
		default:
			entries = append(entries, &BatchNewX509SVIDRequest{
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
		var typeStatus *types.Status
		if bundle.Err != nil {
			// Parse error into grpc status, if status fails to parse it will return an status with `Unknown` status code
			bundleStatus, ok := status.FromError(bundle.Err)
			if !ok {
				log.WithError(bundle.Err).Debug("unable to parse error into GRPC status")
			}
			typeStatus = createStatus(bundleStatus.Code(), bundleStatus.Message())
		}
		resp.Results = append(resp.Results, &svid.BatchNewX509SVIDResponse_Result{
			Status: typeStatus,
			Bundle: parseX509SVID(bundle.Svid),
		})
	}

	return resp, nil
}

// parseNewX509SVIDParams validates and parse provided NewX509SVIDParams
func parseNewX509SVIDParams(svidParam *svid.NewX509SVIDParams, log logrus.FieldLogger) (*x509.CertificateRequest, *types.Status) {
	switch {
	case svidParam.EntryId == "":
		log.Error("Invalid param: missing Entry ID")
		return nil, createStatus(codes.InvalidArgument, "invalid param: missing Entry ID")
	case len(svidParam.Csr) == 0:
		log.WithField(telemetry.RegistrationID, svidParam.EntryId).Error("Invalid param: missing CSR")
		return nil, createStatus(codes.InvalidArgument, "invalid param: bundle %q: missing CSR", svidParam.EntryId)
	}

	csr, err := x509.ParseCertificateRequest(svidParam.Csr)
	if err != nil {
		log.WithField(telemetry.RegistrationID, svidParam.EntryId).WithError(err).Errorf("Invalid Param: invalid CSR")
		return nil, createStatus(codes.InvalidArgument, "invalid param: entry  %q: invalid CSR", svidParam.EntryId)
	}

	return csr, nil
}

func (s server) NewJWTSVID(context.Context, *svid.NewJWTSVIDRequest) (*svid.NewJWTSVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (s server) NewDownstreamX509CA(context.Context, *svid.NewDownstreamX509CARequest) (*svid.NewDownstreamX509CAResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

// createStatus creates an Status
func createStatus(code codes.Code, format string, a ...interface{}) *types.Status {
	return &types.Status{
		Code:    int32(code),
		Message: fmt.Sprintf(format, a...),
	}
}

func parseX509SVID(x509SVID *api.X509SVID) *types.X509SVID {
	return &types.X509SVID{
		Id: &types.SPIFFEID{
			TrustDomain: x509SVID.ID.TrustDomain().String(),
			Path:        x509SVID.ID.Path(),
		},
		CertChain: x509util.RawCertsFromCertificates(x509SVID.CertChain),
		ExpiresAt: x509SVID.ExpiresAt.Unix(),
	}
}
