package upstreamauthority_test

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/common"
	upstreamauthorityv0 "github.com/spiffe/spire/proto/spire/server/upstreamauthority/v0"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/testing/protocmp"
)

const (
	csr          = "CSR"
	preferredTTL = time.Minute
)

var (
	jwtKey = &common.PublicKey{Kid: "KEYID", PkixBytes: []byte("PKIXDATA"), NotAfter: 12345}
)

func TestV0MintX509CA(t *testing.T) {
	upstreamCA := testca.New(t, spiffeid.RequireTrustDomainFromString("example.org"))
	x509CA := upstreamCA.ChildCA()

	expectedX509CAChain := x509CA.X509Authorities()
	expectedUpstreamX509Roots := upstreamCA.X509Authorities()

	validX509CAChain := x509util.RawCertsFromCertificates(expectedX509CAChain)
	validUpstreamX509Roots := x509util.RawCertsFromCertificates(expectedUpstreamX509Roots)
	malformedX509CAChain := [][]byte{[]byte("OHNO")}
	malformedUpstreamX509Roots := [][]byte{[]byte("OHNO")}

	withoutX509CAChain := &upstreamauthorityv0.MintX509CAResponse{
		X509CaChain:       nil,
		UpstreamX509Roots: validUpstreamX509Roots,
	}
	withoutUpstreamX509Roots := &upstreamauthorityv0.MintX509CAResponse{
		X509CaChain:       validX509CAChain,
		UpstreamX509Roots: nil,
	}
	withMalformedX509CAChain := &upstreamauthorityv0.MintX509CAResponse{
		X509CaChain:       malformedX509CAChain,
		UpstreamX509Roots: validUpstreamX509Roots,
	}
	withMalformedUpstreamX509Roots := &upstreamauthorityv0.MintX509CAResponse{
		X509CaChain:       validX509CAChain,
		UpstreamX509Roots: malformedUpstreamX509Roots,
	}
	withX509CAChainAndUpstreamX509Roots := &upstreamauthorityv0.MintX509CAResponse{
		X509CaChain:       validX509CAChain,
		UpstreamX509Roots: validUpstreamX509Roots,
	}

	builder := BuildV0()

	for _, tt := range []struct {
		test                string
		builder             *V0Builder
		expectCode          codes.Code
		expectMessage       string
		expectStreamUpdates bool
		expectStreamCode    codes.Code
		expectStreamMessage string
		expectLogs          []spiretest.LogEntry
	}{
		{
			test:          "plugin returns before sending first response",
			builder:       builder.WithPreSendError(nil),
			expectCode:    codes.Internal,
			expectMessage: "upstreamauthority(test): plugin closed stream unexpectedly",
		},
		{
			test:          "plugin fails before sending first response",
			builder:       builder.WithPreSendError(errors.New("ohno")),
			expectCode:    codes.Unknown,
			expectMessage: "upstreamauthority(test): ohno",
		},
		{
			test:          "plugin response missing X.509 CA chain",
			builder:       builder.WithMintX509CAResponse(withoutX509CAChain),
			expectCode:    codes.Internal,
			expectMessage: "upstreamauthority(test): plugin response missing X.509 CA chain",
		},
		{
			test:          "plugin response has malformed X.509 CA chain",
			builder:       builder.WithMintX509CAResponse(withMalformedX509CAChain),
			expectCode:    codes.Internal,
			expectMessage: "upstreamauthority(test): plugin response has malformed X.509 CA chain",
		},
		{
			test:          "plugin response missing upstream X.509 roots",
			builder:       builder.WithMintX509CAResponse(withoutUpstreamX509Roots),
			expectCode:    codes.Internal,
			expectMessage: "upstreamauthority(test): plugin response missing upstream X.509 roots",
		},
		{
			test:          "plugin response has malformed upstream X.509 roots",
			builder:       builder.WithMintX509CAResponse(withMalformedUpstreamX509Roots),
			expectCode:    codes.Internal,
			expectMessage: "upstreamauthority(test): plugin response has malformed upstream X.509 roots",
		},
		{
			test:          "success but plugin does not support streaming updates",
			builder:       builder.WithMintX509CAResponse(withX509CAChainAndUpstreamX509Roots),
			expectCode:    codes.OK,
			expectMessage: "",
		},
		{
			test: "success and plugin supports streaming updates",
			builder: builder.
				WithMintX509CAResponse(withX509CAChainAndUpstreamX509Roots).
				WithMintX509CAResponse(withoutX509CAChain),
			expectCode:          codes.OK,
			expectMessage:       "",
			expectStreamUpdates: true,
			expectStreamCode:    codes.OK,
			expectStreamMessage: "",
		},
		{
			test: "second plugin response is bad (contains X.509 CA)",
			builder: builder.
				WithMintX509CAResponse(withX509CAChainAndUpstreamX509Roots).
				WithMintX509CAResponse(withX509CAChainAndUpstreamX509Roots),
			expectCode:          codes.OK,
			expectMessage:       "",
			expectStreamUpdates: false, // because the second response is bad and ignored
			expectStreamCode:    codes.Internal,
			expectStreamMessage: "upstreamauthority(test): plugin response has an X.509 CA chain after the first response",
			expectLogs: []spiretest.LogEntry{
				{Level: logrus.WarnLevel, Message: "Failed to parse an X.509 key update from the upstream authority plugin. Please report this bug."},
			},
		},
		{
			test: "plugin fails to stream updates",
			builder: builder.
				WithMintX509CAResponse(withX509CAChainAndUpstreamX509Roots).
				WithPostSendError(errors.New("ohno")),
			expectCode:          codes.OK,
			expectMessage:       "",
			expectStreamUpdates: true,
			expectStreamCode:    codes.Unknown,
			expectStreamMessage: "upstreamauthority(test): ohno",
		},
	} {
		tt := tt
		t.Run(tt.test, func(t *testing.T) {
			ua := tt.builder.Load(t)
			x509CA, upstreamX509Roots, upstreamX509RootsStream, err := ua.MintX509CA(context.Background(), []byte(csr), preferredTTL)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMessage)
			if tt.expectCode != codes.OK {
				return
			}
			require.NotNil(t, upstreamX509RootsStream, "stream should have been returned")
			defer upstreamX509RootsStream.Close()
			assert.Equal(t, expectedX509CAChain, x509CA)
			assert.Equal(t, expectedUpstreamX509Roots, upstreamX509Roots)

			switch {
			case !tt.expectStreamUpdates:
				upstreamX509Roots, err = upstreamX509RootsStream.RecvUpstreamX509Authorities()
				assert.Equal(t, io.EOF, err, "stream should have returned EOF")
				assert.Nil(t, upstreamX509Roots, "no roots should be received")
			case tt.expectStreamCode == codes.OK:
				upstreamX509Roots, err = upstreamX509RootsStream.RecvUpstreamX509Authorities()
				assert.NoError(t, err, "stream should have returned update")
				assert.Equal(t, expectedUpstreamX509Roots, upstreamX509Roots)
			default:
				upstreamX509Roots, err = upstreamX509RootsStream.RecvUpstreamX509Authorities()
				spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectStreamCode, tt.expectStreamMessage)
				assert.Nil(t, upstreamX509Roots)
			}
		})
	}
}

func TestV0PublishJWTKey(t *testing.T) {
	key := testkey.NewEC256(t)
	pkixBytes, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)

	expectedUpstreamJWTKeys := []*common.PublicKey{
		{
			Kid:       "UPSTREAM KEY",
			PkixBytes: pkixBytes,
		},
	}

	withoutID := &upstreamauthorityv0.PublishJWTKeyResponse{
		UpstreamJwtKeys: []*common.PublicKey{
			{PkixBytes: pkixBytes},
		},
	}
	withoutPKIXData := &upstreamauthorityv0.PublishJWTKeyResponse{
		UpstreamJwtKeys: []*common.PublicKey{
			{Kid: "UPSTREAM KEY"},
		},
	}
	withMalformedPKIXData := &upstreamauthorityv0.PublishJWTKeyResponse{
		UpstreamJwtKeys: []*common.PublicKey{
			{Kid: "UPSTREAM KEY", PkixBytes: []byte("JUNK")},
		},
	}
	withIDAndPKIXData := &upstreamauthorityv0.PublishJWTKeyResponse{
		UpstreamJwtKeys: expectedUpstreamJWTKeys,
	}

	builder := BuildV0()

	for _, tt := range []struct {
		test                string
		builder             *V0Builder
		expectCode          codes.Code
		expectMessage       string
		expectStreamUpdates bool
		expectStreamCode    codes.Code
		expectStreamMessage string
		expectLogs          []spiretest.LogEntry
	}{
		{
			test:          "plugin returns before sending first response",
			builder:       builder.WithPreSendError(nil),
			expectCode:    codes.Internal,
			expectMessage: "upstreamauthority(test): plugin closed stream unexpectedly",
		},
		{
			test:          "plugin fails before sending first response",
			builder:       builder.WithPreSendError(errors.New("ohno")),
			expectCode:    codes.Unknown,
			expectMessage: "upstreamauthority(test): ohno",
		},
		{
			test:          "plugin response missing JWT key ID",
			builder:       builder.WithPublishJWTKeyResponse(withoutID),
			expectCode:    codes.Internal,
			expectMessage: "upstreamauthority(test): plugin response missing ID for JWT key",
		},
		{
			test:          "plugin response missing PKIX data",
			builder:       builder.WithPublishJWTKeyResponse(withoutPKIXData),
			expectCode:    codes.Internal,
			expectMessage: `upstreamauthority(test): plugin response missing PKIX data for JWT key "UPSTREAM KEY"`,
		},
		{
			test:          "plugin response has malformed PKIX data",
			builder:       builder.WithPublishJWTKeyResponse(withMalformedPKIXData),
			expectCode:    codes.Internal,
			expectMessage: `upstreamauthority(test): plugin response has malformed PKIX data for JWT key "UPSTREAM KEY"`,
		},
		{
			test:          "success but plugin does not support streaming updates",
			builder:       builder.WithPublishJWTKeyResponse(withIDAndPKIXData),
			expectCode:    codes.OK,
			expectMessage: "",
		},
		{
			test: "success and plugin supports streaming updates",
			builder: builder.
				WithPublishJWTKeyResponse(withIDAndPKIXData).
				WithPublishJWTKeyResponse(withIDAndPKIXData),
			expectCode:          codes.OK,
			expectMessage:       "",
			expectStreamUpdates: true,
			expectStreamCode:    codes.OK,
			expectStreamMessage: "",
		},
		{
			test: "second plugin response is bad (missing ID)",
			builder: builder.
				WithPublishJWTKeyResponse(withIDAndPKIXData).
				WithPublishJWTKeyResponse(withoutID),
			expectCode:          codes.OK,
			expectMessage:       "",
			expectStreamUpdates: false, // because the second response is bad and ignored
			expectStreamCode:    codes.Internal,
			expectStreamMessage: "upstreamauthority(test): plugin response missing ID for JWT key",
			expectLogs: []spiretest.LogEntry{
				{Level: logrus.WarnLevel, Message: "Failed to parse a JWT key update from the upstream authority plugin. Please report this bug."},
			},
		},
		{
			test: "plugin fails to stream updates",
			builder: builder.
				WithPublishJWTKeyResponse(withIDAndPKIXData).
				WithPostSendError(errors.New("ohno")),
			expectCode:          codes.OK,
			expectMessage:       "",
			expectStreamUpdates: true,
			expectStreamCode:    codes.Unknown,
			expectStreamMessage: "upstreamauthority(test): ohno",
		},
	} {
		tt := tt
		t.Run(tt.test, func(t *testing.T) {
			log, logHook := test.NewNullLogger()

			ua := tt.builder.WithLog(log).Load(t)
			upstreamJWTKeys, upstreamJWTKeysStream, err := ua.PublishJWTKey(context.Background(), jwtKey)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMessage)
			if tt.expectCode != codes.OK {
				return
			}
			require.NotNil(t, upstreamJWTKeysStream, "stream should have been returned")
			defer upstreamJWTKeysStream.Close()
			spiretest.AssertProtoListEqual(t, expectedUpstreamJWTKeys, upstreamJWTKeys)

			switch {
			case !tt.expectStreamUpdates:
				upstreamJWTKeys, err := upstreamJWTKeysStream.RecvUpstreamJWTAuthorities()
				assert.Equal(t, io.EOF, err, "stream should have returned EOF")
				assert.Nil(t, upstreamJWTKeys, "no JWT keys should be received")
			case tt.expectStreamCode == codes.OK:
				upstreamJWTKeys, err := upstreamJWTKeysStream.RecvUpstreamJWTAuthorities()
				assert.NoError(t, err, "stream should have returned update")
				spiretest.AssertProtoListEqual(t, expectedUpstreamJWTKeys, upstreamJWTKeys)
			default:
				upstreamJWTKeys, err = upstreamJWTKeysStream.RecvUpstreamJWTAuthorities()
				spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectStreamCode, tt.expectStreamMessage)
				assert.Nil(t, upstreamJWTKeys)
			}

			spiretest.AssertLogs(t, logHook.AllEntries(), tt.expectLogs)
		})
	}
}

type Builder interface {
	Load(t *testing.T) upstreamauthority.UpstreamAuthority
}

type V0Builder struct {
	p   *v0Plugin
	log logrus.FieldLogger
}

func BuildV0() *V0Builder {
	return new(V0Builder)
}

func (b *V0Builder) WithLog(log logrus.FieldLogger) *V0Builder {
	b = b.clone()
	b.log = log
	return b
}

func (b *V0Builder) WithPreSendError(err error) *V0Builder {
	b = b.clone()
	b.p.preSendErr = &err
	return b
}

func (b *V0Builder) WithPostSendError(err error) *V0Builder {
	b = b.clone()
	b.p.postSendErr = err
	return b
}

func (b *V0Builder) WithMintX509CAResponse(response *upstreamauthorityv0.MintX509CAResponse) *V0Builder {
	b = b.clone()
	b.p.mintX509CAResponses = append(b.p.mintX509CAResponses, response)
	return b
}

func (b *V0Builder) WithPublishJWTKeyResponse(response *upstreamauthorityv0.PublishJWTKeyResponse) *V0Builder {
	b = b.clone()
	b.p.publishJWTKeyResponses = append(b.p.publishJWTKeyResponses, response)
	return b
}

func (b *V0Builder) clone() *V0Builder {
	return &V0Builder{
		p:   b.p.clone(),
		log: b.log,
	}
}

func (b *V0Builder) Load(t *testing.T) upstreamauthority.UpstreamAuthority {
	server := upstreamauthorityv0.PluginServer(b.clone().p)

	var opts []spiretest.PluginOption
	if b.log != nil {
		opts = append(opts, spiretest.Logger(b.log))
	}

	var na upstreamauthority.V0
	spiretest.LoadPlugin(t, catalog.MakePlugin("test", server), &na, opts...)
	return na
}

type v0Plugin struct {
	upstreamauthorityv0.UnimplementedUpstreamAuthorityServer

	preSendErr             *error
	postSendErr            error
	mintX509CAResponses    []*upstreamauthorityv0.MintX509CAResponse
	publishJWTKeyResponses []*upstreamauthorityv0.PublishJWTKeyResponse
}

func (v0 *v0Plugin) MintX509CA(req *upstreamauthorityv0.MintX509CARequest, stream upstreamauthorityv0.UpstreamAuthority_MintX509CAServer) error {
	if string(req.Csr) != string(csr) {
		return errors.New("unexpected CSR")
	}
	if time.Second*time.Duration(req.PreferredTtl) != preferredTTL {
		return errors.New("unexpected preferred TTL")
	}

	if v0.preSendErr != nil {
		return *v0.preSendErr
	}

	for _, response := range v0.mintX509CAResponses {
		if err := stream.Send(response); err != nil {
			return err
		}
	}

	return v0.postSendErr
}

func (v0 *v0Plugin) PublishJWTKey(req *upstreamauthorityv0.PublishJWTKeyRequest, stream upstreamauthorityv0.UpstreamAuthority_PublishJWTKeyServer) error {
	if diff := cmp.Diff(jwtKey, req.JwtKey, protocmp.Transform()); diff != "" {
		return fmt.Errorf("unexpected public key: %s", diff)
	}

	if v0.preSendErr != nil {
		return *v0.preSendErr
	}

	for _, response := range v0.publishJWTKeyResponses {
		if err := stream.Send(response); err != nil {
			return err
		}
	}

	return v0.postSendErr
}

func (v0 *v0Plugin) clone() *v0Plugin {
	if v0 == nil {
		return &v0Plugin{}
	}
	clone := *v0
	return &clone
}
