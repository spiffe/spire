package upstreamauthority

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"time"

	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/pkg/common/coretypes/jwtkey"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
)

type V1 struct {
	plugin.Facade
	upstreamauthorityv1.UpstreamAuthorityPluginClient
}

// MintX509CA provides the V1 implementation of the UpstreamAuthority
// interface method of the same name.
func (v1 *V1) MintX509CA(ctx context.Context, csr []byte, preferredTTL time.Duration) (_, _ []*x509.Certificate, _ UpstreamX509AuthorityStream, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		// Only cancel the context if the function fails. Otherwise the
		// returned stream will be in charge of cancelation.
		if err != nil {
			defer cancel()
		}
	}()

	stream, err := v1.UpstreamAuthorityPluginClient.MintX509CAAndSubscribe(ctx, &upstreamauthorityv1.MintX509CARequest{
		Csr:          csr,
		PreferredTtl: int32(preferredTTL / time.Second),
	})
	if err != nil {
		return nil, nil, nil, v1.WrapErr(err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, nil, nil, v1.streamError(err)
	}

	x509CA, upstreamX509Authorities, err := v1.parseMintX509CAFirstResponse(resp)
	if err != nil {
		return nil, nil, nil, err
	}

	return x509CA, upstreamX509Authorities, &v1UpstreamX509AuthorityStream{v1: v1, stream: stream, cancel: cancel}, nil
}

// PublishJWTKey provides the V1 implementation of the UpstreamAuthority
// interface method of the same name.
func (v1 *V1) PublishJWTKey(ctx context.Context, jwtKey *common.PublicKey) (_ []*common.PublicKey, _ UpstreamJWTAuthorityStream, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		// Only cancel the context if the function fails. Otherwise the
		// returned stream will be in charge of cancelation.
		if err != nil {
			defer cancel()
		}
	}()

	pluginJWTKey, err := jwtkey.ToPluginFromCommonProto(jwtKey)
	if err != nil {
		return nil, nil, err
	}

	stream, err := v1.UpstreamAuthorityPluginClient.PublishJWTKeyAndSubscribe(ctx, &upstreamauthorityv1.PublishJWTKeyRequest{
		JwtKey: pluginJWTKey,
	})
	if err != nil {
		return nil, nil, v1.WrapErr(err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, nil, v1.streamError(err)
	}

	jwtKeys, err := v1.toCommonProtos(resp.UpstreamJwtKeys)
	if err != nil {
		return nil, nil, err
	}

	return jwtKeys, &v1UpstreamJWTAuthorityStream{v1: v1, stream: stream, cancel: cancel}, nil
}

func (v1 *V1) parseMintX509CAFirstResponse(resp *upstreamauthorityv1.MintX509CAResponse) ([]*x509.Certificate, []*x509.Certificate, error) {
	x509CA, err := x509certificate.FromPluginProtos(resp.X509CaChain)
	if err != nil {
		return nil, nil, v1.Errorf(codes.Internal, "plugin response has malformed X.509 CA chain: %v", err)
	}
	if len(x509CA) == 0 {
		return nil, nil, v1.Error(codes.Internal, "plugin response missing X.509 CA chain")
	}
	x509Authorities, err := v1.parseX509Authorities(resp.UpstreamX509Roots)
	if err != nil {
		return nil, nil, err
	}
	return x509CA, x509Authorities, nil
}

func (v1 *V1) parseMintX509CABundleUpdate(resp *upstreamauthorityv1.MintX509CAResponse) ([]*x509.Certificate, error) {
	if len(resp.X509CaChain) > 0 {
		return nil, v1.Error(codes.Internal, "plugin response has an X.509 CA chain after the first response")
	}
	return v1.parseX509Authorities(resp.UpstreamX509Roots)
}

func (v1 *V1) parseX509Authorities(rawX509Authorities []*types.X509Certificate) ([]*x509.Certificate, error) {
	x509Authorities, err := x509certificate.FromPluginProtos(rawX509Authorities)
	if err != nil {
		return nil, v1.Errorf(codes.Internal, "plugin response has malformed upstream X.509 roots: %v", err)
	}
	if len(x509Authorities) == 0 {
		return nil, v1.Error(codes.Internal, "plugin response missing upstream X.509 roots")
	}
	return x509Authorities, nil
}

func (v1 *V1) streamError(err error) error {
	if errors.Is(err, io.EOF) {
		return v1.Error(codes.Internal, "plugin closed stream unexpectedly")
	}
	return v1.WrapErr(err)
}

func (v1 *V1) toCommonProtos(pbs []*types.JWTKey) ([]*common.PublicKey, error) {
	jwtKeys, err := jwtkey.ToCommonFromPluginProtos(pbs)
	if err != nil {
		return nil, v1.Errorf(codes.Internal, "invalid plugin response: %v", err)
	}
	return jwtKeys, nil
}

type v1UpstreamX509AuthorityStream struct {
	v1     *V1
	stream upstreamauthorityv1.UpstreamAuthority_MintX509CAAndSubscribeClient
	cancel context.CancelFunc
}

func (s *v1UpstreamX509AuthorityStream) RecvUpstreamX509Authorities() ([]*x509.Certificate, error) {
	for {
		resp, err := s.stream.Recv()
		switch {
		case errors.Is(err, io.EOF):
			// This is expected if the plugin does not support streaming
			// authority updates.
			return nil, err
		case err != nil:
			return nil, s.v1.WrapErr(err)
		}

		x509Authorities, err := s.v1.parseMintX509CABundleUpdate(resp)
		if err != nil {
			s.v1.Log.WithError(err).Warn("Failed to parse an X.509 root update from the upstream authority plugin. Please report this bug.")
			continue
		}
		return x509Authorities, nil
	}
}

func (s *v1UpstreamX509AuthorityStream) Close() {
	s.cancel()
}

type v1UpstreamJWTAuthorityStream struct {
	v1     *V1
	stream upstreamauthorityv1.UpstreamAuthority_PublishJWTKeyAndSubscribeClient
	cancel context.CancelFunc
}

func (s *v1UpstreamJWTAuthorityStream) RecvUpstreamJWTAuthorities() ([]*common.PublicKey, error) {
	for {
		resp, err := s.stream.Recv()
		switch {
		case errors.Is(err, io.EOF):
			// This is expected if the plugin does not support streaming
			// authority updates.
			return nil, io.EOF
		case err != nil:
			return nil, s.v1.WrapErr(err)
		}

		jwtKeys, err := s.v1.toCommonProtos(resp.UpstreamJwtKeys)
		if err != nil {
			s.v1.Log.WithError(err).Warn("Failed to parse a JWT key update from the upstream authority plugin. Please report this bug.")
			continue
		}
		return jwtKeys, nil
	}
}

func (s *v1UpstreamJWTAuthorityStream) Close() {
	s.cancel()
}
