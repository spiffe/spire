package bundle

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire-next/api/server/bundle/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RegisterService registers the bundle service on the gRPC server.
func RegisterService(s *grpc.Server, c *Config) {
	srv := service{c: c}
	bundle.RegisterBundleServer(s, srv)
}

type service struct {
	c *Config
}

type Config struct {
	ds datastore.DataStore
}

func (s service) GetBundle(ctx context.Context, req *bundle.GetBundleRequest) (*types.Bundle, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetBundle not implemented")
}

func (s service) AppendBundle(ctx context.Context, req *bundle.AppendBundleRequest) (*types.Bundle, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AppendBundle not implemented")
}

func (s service) ListFederatedBundles(ctx context.Context, req *bundle.ListFederatedBundlesRequest) (*bundle.ListFederatedBundlesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListFederatedBundles not implemented")
}

func (s service) GetFederatedBundle(ctx context.Context, req *bundle.GetFederatedBundleRequest) (*types.Bundle, error) {
	log := rpccontext.Logger(ctx).WithField("RPC", "GetFedertedBundle")

	if !(rpccontext.CallerIsLocal(ctx) || rpccontext.CallerIsAdmin(ctx) || rpccontext.CallerIsAgent(ctx)) {
		log.Errorf("Permission denied: the caller must be local or present an admin or an active agent X509-SVID")
		return nil, status.Errorf(codes.PermissionDenied, "the caller must be local or present an admin or an active agent X509-SVID")
	}

	callerID, ok := rpccontext.CallerID(ctx)
	if !ok {
		log.Error("Cannot get SPIFFE ID from caller")
		return nil, status.Error(codes.Internal, "cannot get SPIFFE ID from caller")
	}

	reqTrustDomainID, err := spiffeid.FromString(req.TrustDomain)
	if err != nil {
		log.Errorf("Trust domain argument is not a valid SPIFFE ID: %q", req.TrustDomain)
		return nil, status.Errorf(codes.InvalidArgument, "trust domain argument is not a valid SPIFFE ID: %q", req.TrustDomain)
	}

	if reqTrustDomainID.Empty() {
		log.Error("Trust domain argument is empty")
		return nil, status.Errorf(codes.InvalidArgument, "trust domain argument is empty")
	}

	if reqTrustDomainID.Path() != "" {
		log.Warnf("Using a full SPIFFE ID as trust domain argument, path section will be ignored: %q", reqTrustDomainID.String())
	}

	if callerID.MemberOf(reqTrustDomainID.TrustDomain()) {
		log.Errorf("%q is your own trust domain, use GetBundle RPC instead", reqTrustDomainID.TrustDomain())
		return nil, status.Errorf(codes.InvalidArgument, "%q is your own trust domain, use GetBundle RPC instead", reqTrustDomainID.TrustDomain())
	}

	dsResp, err := s.c.ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: req.TrustDomain,
	})
	if err != nil {
		log.Errorf("Failed to fetch bundle: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to fetch bundle: %v", err)
	}

	if dsResp.Bundle == nil {
		log.Errorf("Bundle for %q not found", req.TrustDomain)
		return nil, status.Errorf(codes.NotFound, "bundle for %q not found", req.TrustDomain)
	}

	resp := &types.Bundle{}
	if req.OutputMask.TrustDomainId {
		resp.TrustDomainId.TrustDomain = dsResp.Bundle.TrustDomainId
	}

	if req.OutputMask.RefreshHint {
		resp.RefreshHint = dsResp.Bundle.RefreshHint
	}

	if req.OutputMask.SequenceNumber {
		//TODO: Where do we get the sequence number from?
		// There is not a `dsResp.Bundle.SequenceNumber` field
		resp.SequenceNumber = 0
	}

	if req.OutputMask.X509Authorities {
		authorities := []*types.X509Certificate{}
		for _, rootCA := range dsResp.Bundle.RootCas {
			authorities = append(authorities, &types.X509Certificate{
				Asn1: rootCA.DerBytes,
			})
		}
		resp.X509Authorities = authorities
	}

	if req.OutputMask.JwtAuthorities {
		authorities := []*types.JWTKey{}
		for _, JWTSigningKey := range dsResp.Bundle.JwtSigningKeys {
			authorities = append(authorities, &types.JWTKey{
				PublicKey: JWTSigningKey.PkixBytes,
				KeyId:     JWTSigningKey.Kid,
				ExpiresAt: JWTSigningKey.NotAfter,
			})
		}
		resp.JwtAuthorities = authorities
	}

	return resp, nil
}

func (s service) BatchCreateFederatedBundle(ctx context.Context, req *bundle.BatchCreateFederatedBundleRequest) (*bundle.BatchCreateFederatedBundleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method BatchCreateFederatedBundle not implemented")
}

func (s service) BatchUpdateFederatedBundle(ctx context.Context, req *bundle.BatchUpdateFederatedBundleRequest) (*bundle.BatchUpdateFederatedBundleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method BatchUpdateFederatedBundle not implemented")
}

func (s service) BatchSetFederatedBundle(ctx context.Context, req *bundle.BatchSetFederatedBundleRequest) (*bundle.BatchSetFederatedBundleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method BatchSetFederatedBundle not implemented")
}

func (s service) BatchDeleteFederatedBundle(ctx context.Context, req *bundle.BatchDeleteFederatedBundleRequest) (*bundle.BatchDeleteFederatedBundleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method BatchDeleteFederatedBundle not implemented")
}
