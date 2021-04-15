package upstreamauthority

import (
	"context"
	"crypto/x509"
	"io"
	"time"

	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
	upstreamauthorityv0 "github.com/spiffe/spire/proto/spire/plugin/server/upstreamauthority/v0"
	"google.golang.org/grpc/codes"
)

type V0 struct {
	plugin.Facade

	Log    plugin.Log
	Plugin upstreamauthorityv0.UpstreamAuthority
}

// MintX509CA provides the V0 implementation of the UpstreamAuthority
// interface method of the same name.
func (v0 V0) MintX509CA(ctx context.Context, csr []byte, preferredTTL time.Duration) (_, _ []*x509.Certificate, _ UpstreamX509AuthorityStream, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		// Only cancel the context if the function fails. Otherwise the
		// returned stream will be in charge of cancelation.
		if err != nil {
			defer cancel()
		}
	}()

	stream, err := v0.Plugin.MintX509CA(ctx, &upstreamauthorityv0.MintX509CARequest{
		Csr:          csr,
		PreferredTtl: int32(preferredTTL / time.Second),
	})
	if err != nil {
		return nil, nil, nil, v0.WrapErr(err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, nil, nil, v0.streamError(err)
	}

	x509CA, upstreamX509Authorities, err := v0.parseMintX509CAFirstResponse(resp)
	if err != nil {
		return nil, nil, nil, err
	}

	return x509CA, upstreamX509Authorities, &v0UpstreamX509AuthorityStream{v0: v0, stream: stream, cancel: cancel}, nil
}

// PublishJWTKey provides the V0 implementation of the UpstreamAuthority
// interface method of the same name.
func (v0 V0) PublishJWTKey(ctx context.Context, jwtKey *common.PublicKey) (_ []*common.PublicKey, _ UpstreamJWTAuthorityStream, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		// Only cancel the context if the function fails. Otherwise the
		// returned stream will be in charge of cancelation.
		if err != nil {
			defer cancel()
		}
	}()

	stream, err := v0.Plugin.PublishJWTKey(ctx, &upstreamauthorityv0.PublishJWTKeyRequest{
		JwtKey: jwtKey,
	})
	if err != nil {
		return nil, nil, v0.WrapErr(err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, nil, v0.streamError(err)
	}

	if err := v0.validateJWTKeys(resp.UpstreamJwtKeys); err != nil {
		return nil, nil, err
	}

	return resp.UpstreamJwtKeys, &v0UpstreamJWTAuthorityStream{v0: v0, stream: stream, cancel: cancel}, nil
}

func (v0 V0) parseMintX509CAFirstResponse(resp *upstreamauthorityv0.MintX509CAResponse) ([]*x509.Certificate, []*x509.Certificate, error) {
	x509CA, err := x509util.RawCertsToCertificates(resp.X509CaChain)
	if err != nil {
		return nil, nil, v0.Errorf(codes.Internal, "plugin response has malformed X.509 CA chain: %v", err)
	}
	if len(x509CA) == 0 {
		return nil, nil, v0.Error(codes.Internal, "plugin response missing X.509 CA chain")
	}
	x509Authorities, err := v0.parseX509Authorities(resp.UpstreamX509Roots)
	if err != nil {
		return nil, nil, err
	}
	return x509CA, x509Authorities, nil
}

func (v0 V0) parseMintX509CABundleUpdate(resp *upstreamauthorityv0.MintX509CAResponse) ([]*x509.Certificate, error) {
	if len(resp.X509CaChain) > 0 {
		return nil, v0.Error(codes.Internal, "plugin response has an X.509 CA chain after the first response")
	}
	return v0.parseX509Authorities(resp.UpstreamX509Roots)
}

func (v0 V0) parseX509Authorities(rawX509Authorities [][]byte) ([]*x509.Certificate, error) {
	x509Authorities, err := x509util.RawCertsToCertificates(rawX509Authorities)
	if err != nil {
		return nil, v0.Errorf(codes.Internal, "plugin response has malformed upstream X.509 roots: %v", err)
	}
	if len(x509Authorities) == 0 {
		return nil, v0.Error(codes.Internal, "plugin response missing upstream X.509 roots")
	}
	return x509Authorities, nil
}

func (v0 V0) validateJWTKeys(jwtKeys []*common.PublicKey) error {
	for _, jwtKey := range jwtKeys {
		if jwtKey.Kid == "" {
			return v0.Error(codes.Internal, "plugin response missing ID for JWT key")
		}
		if jwtKey.PkixBytes == nil {
			return v0.Errorf(codes.Internal, "plugin response missing PKIX data for JWT key %q", jwtKey.Kid)
		}
		if _, err := x509.ParsePKIXPublicKey(jwtKey.PkixBytes); err != nil {
			return v0.Errorf(codes.Internal, "plugin response has malformed PKIX data for JWT key %q: %v", jwtKey.Kid, err)
		}
	}
	return nil
}

func (v0 V0) streamError(err error) error {
	if err == io.EOF {
		return v0.Error(codes.Internal, "plugin closed stream unexpectedly")
	}
	return v0.WrapErr(err)
}

type v0UpstreamX509AuthorityStream struct {
	v0     V0
	stream upstreamauthorityv0.UpstreamAuthority_MintX509CAClient
	cancel context.CancelFunc
}

func (s *v0UpstreamX509AuthorityStream) RecvUpstreamX509Authorities() ([]*x509.Certificate, error) {
	for {
		resp, err := s.stream.Recv()
		switch {
		case err == io.EOF:
			// This is expected if the plugin does not support streaming
			// authority updates.
			return nil, err
		case err != nil:
			return nil, s.v0.WrapErr(err)
		}

		x509Authorities, err := s.v0.parseMintX509CABundleUpdate(resp)
		if err != nil {
			s.v0.Log.WithError(err).Warn("Failed to parse an X.509 root update from the upstream authority plugin. Please report this bug.")
			continue
		}
		return x509Authorities, nil
	}
}

func (s *v0UpstreamX509AuthorityStream) Close() {
	s.cancel()
}

type v0UpstreamJWTAuthorityStream struct {
	v0     V0
	stream upstreamauthorityv0.UpstreamAuthority_PublishJWTKeyClient
	cancel context.CancelFunc
}

func (s *v0UpstreamJWTAuthorityStream) RecvUpstreamJWTAuthorities() ([]*common.PublicKey, error) {
	for {
		resp, err := s.stream.Recv()
		switch {
		case err == io.EOF:
			// This is expected if the plugin does not support streaming
			// authority updates.
			return nil, io.EOF
		case err != nil:
			return nil, s.v0.WrapErr(err)
		}

		if err := s.v0.validateJWTKeys(resp.UpstreamJwtKeys); err != nil {
			s.v0.Log.WithError(err).Warn("Failed to parse a JWT key update from the upstream authority plugin. Please report this bug.")
			continue
		}
		return resp.UpstreamJwtKeys, nil
	}
}

func (s *v0UpstreamJWTAuthorityStream) Close() {
	s.cancel()
}
