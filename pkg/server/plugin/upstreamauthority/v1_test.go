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
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/coretypes/jwtkey"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/plugintest"
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
	jwtKeyPKIX, _ = x509.MarshalPKIXPublicKey(testkey.MustEC256().Public())
	jwtKey        = &common.PublicKey{Kid: "KEYID", PkixBytes: jwtKeyPKIX, NotAfter: 12345}
)

func TestV1MintX509CA(t *testing.T) {
	upstreamCA := testca.New(t, spiffeid.RequireTrustDomainFromString("example.org"))
	x509CA := upstreamCA.ChildCA()

	expectedX509CAChain := x509CA.X509Authorities()
	var expectedUpstreamX509Roots []*x509certificate.X509Authority
	for _, eachCert := range upstreamCA.X509Authorities() {
		expectedUpstreamX509Roots = append(expectedUpstreamX509Roots, &x509certificate.X509Authority{
			Certificate: eachCert,
		})
	}
	taintedUpstreamX509Roots := []*x509certificate.X509Authority{
		{
			Certificate: expectedUpstreamX509Roots[0].Certificate,
			Tainted:     true,
		},
	}

	validX509CAChain := x509certificate.RequireToPluginFromCertificates(expectedX509CAChain)
	validUpstreamX509Roots := x509certificate.RequireToPluginProtos(expectedUpstreamX509Roots)
	malformedX509CAChain := []*types.X509Certificate{{Asn1: []byte("OHNO")}}
	malformedUpstreamX509Roots := []*types.X509Certificate{{Asn1: []byte("OHNO")}}
	withoutX509CAChain := &upstreamauthorityv1.MintX509CAResponse{
		X509CaChain:       nil,
		UpstreamX509Roots: validUpstreamX509Roots,
	}
	withoutUpstreamX509Roots := &upstreamauthorityv1.MintX509CAResponse{
		X509CaChain:       validX509CAChain,
		UpstreamX509Roots: nil,
	}
	withMalformedX509CAChain := &upstreamauthorityv1.MintX509CAResponse{
		X509CaChain:       malformedX509CAChain,
		UpstreamX509Roots: validUpstreamX509Roots,
	}
	withMalformedUpstreamX509Roots := &upstreamauthorityv1.MintX509CAResponse{
		X509CaChain:       validX509CAChain,
		UpstreamX509Roots: malformedUpstreamX509Roots,
	}
	withX509CAChainAndUpstreamX509Roots := &upstreamauthorityv1.MintX509CAResponse{
		X509CaChain:       validX509CAChain,
		UpstreamX509Roots: validUpstreamX509Roots,
	}
	withTaintedUpstreamX509Roots := &upstreamauthorityv1.MintX509CAResponse{
		X509CaChain: validX509CAChain,
		UpstreamX509Roots: []*types.X509Certificate{
			{
				Asn1:    validUpstreamX509Roots[0].Asn1,
				Tainted: true,
			},
		},
	}

	builder := BuildV1()

	for _, tt := range []struct {
		test                            string
		builder                         *V1Builder
		expectCode                      codes.Code
		expectMessage                   string
		expectStreamUpdates             bool
		expectStreamCode                codes.Code
		expectStreamMessage             string
		expectLogs                      []spiretest.LogEntry
		expectUpstreamX509RootsResponse []*x509certificate.X509Authority
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
			test: "success with tainted authority",
			builder: builder.
				WithMintX509CAResponse(withTaintedUpstreamX509Roots),
			expectCode:                      codes.OK,
			expectMessage:                   "",
			expectStreamUpdates:             false,
			expectUpstreamX509RootsResponse: taintedUpstreamX509Roots,
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
				{
					Level:   logrus.WarnLevel,
					Message: "Failed to parse an X.509 root update from the upstream authority plugin. Please report this bug.",
					Data: logrus.Fields{
						logrus.ErrorKey: "rpc error: code = Internal desc = upstreamauthority(test): plugin response has an X.509 CA chain after the first response",
					},
				},
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
		t.Run(tt.test, func(t *testing.T) {
			log, logHook := test.NewNullLogger()

			ua := tt.builder.WithLog(log).Load(t)
			x509CA, upstreamX509Roots, upstreamX509RootsStream, err := ua.MintX509CA(context.Background(), []byte(csr), preferredTTL)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMessage)
			if tt.expectCode != codes.OK {
				return
			}
			require.NotNil(t, upstreamX509RootsStream, "stream should have been returned")
			defer upstreamX509RootsStream.Close()
			expectUpstreamX509Roots := expectedUpstreamX509Roots
			if tt.expectUpstreamX509RootsResponse != nil {
				expectUpstreamX509Roots = tt.expectUpstreamX509RootsResponse
			}
			assert.Equal(t, expectedX509CAChain, x509CA)
			assert.Equal(t, expectUpstreamX509Roots, upstreamX509Roots)

			switch {
			case !tt.expectStreamUpdates:
				upstreamX509Roots, err = upstreamX509RootsStream.RecvUpstreamX509Authorities()
				assert.Equal(t, io.EOF, err, "stream should have returned EOF")
				assert.Nil(t, upstreamX509Roots, "no roots should be received")
			case tt.expectStreamCode == codes.OK:
				upstreamX509Roots, err = upstreamX509RootsStream.RecvUpstreamX509Authorities()
				assert.NoError(t, err, "stream should have returned update")
				expected := expectUpstreamX509Roots
				if tt.expectUpstreamX509RootsResponse != nil {
					expected = tt.expectUpstreamX509RootsResponse
				}
				assert.Equal(t, expected, upstreamX509Roots)
			default:
				upstreamX509Roots, err = upstreamX509RootsStream.RecvUpstreamX509Authorities()
				spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectStreamCode, tt.expectStreamMessage)
				assert.Nil(t, upstreamX509Roots)
			}

			spiretest.AssertLogs(t, logHook.AllEntries(), tt.expectLogs)
		})
	}
}

func TestV1PublishJWTKey(t *testing.T) {
	key := testkey.NewEC256(t)
	pkixBytes, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)

	expectedUpstreamJWTKeys := []*common.PublicKey{
		{
			Kid:       "UPSTREAM KEY",
			PkixBytes: pkixBytes,
		},
	}

	withoutID := &upstreamauthorityv1.PublishJWTKeyResponse{
		UpstreamJwtKeys: []*types.JWTKey{
			{PublicKey: pkixBytes},
		},
	}
	withoutPKIXData := &upstreamauthorityv1.PublishJWTKeyResponse{
		UpstreamJwtKeys: []*types.JWTKey{
			{KeyId: "UPSTREAM KEY"},
		},
	}
	withMalformedPKIXData := &upstreamauthorityv1.PublishJWTKeyResponse{
		UpstreamJwtKeys: []*types.JWTKey{
			{KeyId: "UPSTREAM KEY", PublicKey: []byte("JUNK")},
		},
	}
	withIDAndPKIXData := &upstreamauthorityv1.PublishJWTKeyResponse{
		UpstreamJwtKeys: jwtkey.RequireToPluginFromCommonProtos(expectedUpstreamJWTKeys),
	}

	builder := BuildV1()

	for _, tt := range []struct {
		test                string
		builder             *V1Builder
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
			expectMessage: "upstreamauthority(test): invalid plugin response: missing key ID for JWT key",
		},
		{
			test:          "plugin response missing PKIX data",
			builder:       builder.WithPublishJWTKeyResponse(withoutPKIXData),
			expectCode:    codes.Internal,
			expectMessage: `upstreamauthority(test): invalid plugin response: missing public key for JWT key "UPSTREAM KEY"`,
		},
		{
			test:          "plugin response has malformed PKIX data",
			builder:       builder.WithPublishJWTKeyResponse(withMalformedPKIXData),
			expectCode:    codes.Internal,
			expectMessage: `upstreamauthority(test): invalid plugin response: failed to unmarshal public key for JWT key "UPSTREAM KEY"`,
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
				{
					Level:   logrus.WarnLevel,
					Message: "Failed to parse a JWT key update from the upstream authority plugin. Please report this bug.",
					Data: logrus.Fields{
						logrus.ErrorKey: "rpc error: code = Internal desc = upstreamauthority(test): invalid plugin response: missing key ID for JWT key",
					},
				},
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

func TestV1SubscribeToLocalBundle(t *testing.T) {
	upstreamCA := testca.New(t, spiffeid.RequireTrustDomainFromString("example.org"))

	var expectedUpstreamX509Roots []*x509certificate.X509Authority
	for _, eachCert := range upstreamCA.X509Authorities() {
		expectedUpstreamX509Roots = append(expectedUpstreamX509Roots, &x509certificate.X509Authority{
			Certificate: eachCert,
		})
	}
	validUpstreamX509Roots := x509certificate.RequireToPluginProtos(expectedUpstreamX509Roots)

	key := testkey.NewEC256(t)
	pkixBytes, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)

	expectedUpstreamJWTKeys := []*common.PublicKey{
		{
			Kid:       "UPSTREAM KEY",
			PkixBytes: pkixBytes,
		},
	}
	noJwtAuthorities := &upstreamauthorityv1.SubscribeToLocalBundleResponse{
		UpstreamX509Roots: validUpstreamX509Roots,
	}

	fullResponse := &upstreamauthorityv1.SubscribeToLocalBundleResponse{
		UpstreamX509Roots: validUpstreamX509Roots,
		UpstreamJwtKeys:   jwtkey.RequireToPluginFromCommonProtos(expectedUpstreamJWTKeys),
	}

	builder := BuildV1()
	for _, tt := range []struct {
		test                            string
		builder                         *V1Builder
		expectCode                      codes.Code
		expectMessage                   string
		expectStreamUpdates             bool
		expectStreamCode                codes.Code
		expectStreamMessage             string
		expectLogs                      []spiretest.LogEntry
		expectUpstreamX509RootsResponse []*x509certificate.X509Authority
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
			test:                "success with empty JWT authorities",
			builder:             builder.WithSubscribeToLocalBundleResponse(noJwtAuthorities),
			expectCode:          codes.OK,
			expectMessage:       "",
			expectStreamUpdates: false,
		},
		{
			test:                "success but plugin does not support streaming updates",
			builder:             builder.WithSubscribeToLocalBundleResponse(fullResponse),
			expectCode:          codes.OK,
			expectMessage:       "",
			expectStreamUpdates: false,
		},
		{
			test: "success and plugin supports streaming updates",
			builder: builder.
				WithSubscribeToLocalBundleResponse(noJwtAuthorities).
				WithSubscribeToLocalBundleResponse(fullResponse),
			expectCode:                      codes.OK,
			expectMessage:                   "",
			expectStreamUpdates:             true,
			expectStreamCode:                codes.OK,
			expectStreamMessage:             "",
			expectUpstreamX509RootsResponse: expectedUpstreamX509Roots,
		},
		{
			test: "plugin fails to stream updates",
			builder: builder.
				WithSubscribeToLocalBundleResponse(fullResponse).
				WithPostSendError(errors.New("ohno")),
			expectCode:          codes.OK,
			expectMessage:       "",
			expectStreamUpdates: true,
			expectStreamCode:    codes.Unknown,
			expectStreamMessage: "upstreamauthority(test): ohno",
		},
	} {
		t.Run(tt.test, func(t *testing.T) {
			log, logHook := test.NewNullLogger()

			ua := tt.builder.WithLog(log).Load(t)

			_, _, stream, err := ua.SubscribeToLocalBundle(t.Context())
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMessage)
			if tt.expectCode != codes.OK {
				return
			}
			require.NotNil(t, stream, "valid stream should have been returned")
			defer stream.Close()

			expectUpstreamX509Roots := expectedUpstreamX509Roots
			if tt.expectUpstreamX509RootsResponse != nil {
				expectUpstreamX509Roots = tt.expectUpstreamX509RootsResponse
			}

			upstreamX509Roots, upstreamJWTKeys, err := stream.RecvLocalBundleUpdate()
			switch {
			case !tt.expectStreamUpdates:
				assert.Equal(t, io.EOF, err, "stream should have returned EOF")
				assert.Nil(t, upstreamX509Roots, "no roots should be received")
				assert.Nil(t, upstreamJWTKeys, "no keys should be received")
			case tt.expectStreamCode == codes.OK:
				assert.NoError(t, err, "stream should have returned update")
				expected := expectUpstreamX509Roots
				if tt.expectUpstreamX509RootsResponse != nil {
					expected = tt.expectUpstreamX509RootsResponse
				}
				assert.Equal(t, expected, upstreamX509Roots)
				spiretest.AssertProtoListEqual(t, expectedUpstreamJWTKeys, upstreamJWTKeys)
			default:
				spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectStreamCode, tt.expectStreamMessage)
				assert.Nil(t, upstreamX509Roots)
				assert.Nil(t, upstreamJWTKeys)
			}

			spiretest.AssertLogs(t, logHook.AllEntries(), tt.expectLogs)
		})
	}
}

type V1Builder struct {
	p   *v1Plugin
	log logrus.FieldLogger
}

func BuildV1() *V1Builder {
	return new(V1Builder)
}

func (b *V1Builder) WithLog(log logrus.FieldLogger) *V1Builder {
	b = b.clone()
	b.log = log
	return b
}

func (b *V1Builder) WithPreSendError(err error) *V1Builder {
	b = b.clone()
	b.p.preSendErr = &err
	return b
}

func (b *V1Builder) WithPostSendError(err error) *V1Builder {
	b = b.clone()
	b.p.postSendErr = err
	return b
}

func (b *V1Builder) WithMintX509CAResponse(response *upstreamauthorityv1.MintX509CAResponse) *V1Builder {
	b = b.clone()
	b.p.mintX509CAResponses = append(b.p.mintX509CAResponses, response)
	return b
}

func (b *V1Builder) WithPublishJWTKeyResponse(response *upstreamauthorityv1.PublishJWTKeyResponse) *V1Builder {
	b = b.clone()
	b.p.publishJWTKeyResponses = append(b.p.publishJWTKeyResponses, response)
	return b
}

func (b *V1Builder) WithSubscribeToLocalBundleResponse(response *upstreamauthorityv1.SubscribeToLocalBundleResponse) *V1Builder {
	b = b.clone()
	b.p.subscribeToLocalBundleResponses = append(b.p.subscribeToLocalBundleResponses, response)
	return b
}

func (b *V1Builder) clone() *V1Builder {
	return &V1Builder{
		p:   b.p.clone(),
		log: b.log,
	}
}

func (b *V1Builder) Load(t *testing.T) upstreamauthority.UpstreamAuthority {
	server := upstreamauthorityv1.UpstreamAuthorityPluginServer(b.clone().p)

	var opts []plugintest.Option
	if b.log != nil {
		opts = append(opts, plugintest.Log(b.log))
	}

	ua := new(upstreamauthority.V1)
	plugintest.Load(t, catalog.MakeBuiltIn("test", server), ua, opts...)
	return ua
}

type v1Plugin struct {
	upstreamauthorityv1.UnimplementedUpstreamAuthorityServer

	preSendErr                      *error
	postSendErr                     error
	mintX509CAResponses             []*upstreamauthorityv1.MintX509CAResponse
	publishJWTKeyResponses          []*upstreamauthorityv1.PublishJWTKeyResponse
	subscribeToLocalBundleResponses []*upstreamauthorityv1.SubscribeToLocalBundleResponse
}

func (v1 *v1Plugin) MintX509CAAndSubscribe(req *upstreamauthorityv1.MintX509CARequest, stream upstreamauthorityv1.UpstreamAuthority_MintX509CAAndSubscribeServer) error {
	if string(req.Csr) != string(csr) {
		return errors.New("unexpected CSR")
	}
	if time.Second*time.Duration(req.PreferredTtl) != preferredTTL {
		return errors.New("unexpected preferred TTL")
	}

	if v1.preSendErr != nil {
		return *v1.preSendErr
	}

	for _, response := range v1.mintX509CAResponses {
		if err := stream.Send(response); err != nil {
			return err
		}
	}

	return v1.postSendErr
}

func (v1 *v1Plugin) PublishJWTKeyAndSubscribe(req *upstreamauthorityv1.PublishJWTKeyRequest, stream upstreamauthorityv1.UpstreamAuthority_PublishJWTKeyAndSubscribeServer) error {
	if diff := cmp.Diff(jwtkey.RequireToPluginFromCommonProto(jwtKey), req.JwtKey, protocmp.Transform()); diff != "" {
		return fmt.Errorf("unexpected public key: %s", diff)
	}

	if v1.preSendErr != nil {
		return *v1.preSendErr
	}

	for _, response := range v1.publishJWTKeyResponses {
		if err := stream.Send(response); err != nil {
			return err
		}
	}

	return v1.postSendErr
}

func (v1 *v1Plugin) SubscribeToLocalBundle(req *upstreamauthorityv1.SubscribeToLocalBundleRequest, stream upstreamauthorityv1.UpstreamAuthority_SubscribeToLocalBundleServer) error {
	if v1.preSendErr != nil {
		return *v1.preSendErr
	}

	for _, response := range v1.subscribeToLocalBundleResponses {
		if err := stream.Send(response); err != nil {
			return err
		}
	}

	return v1.postSendErr
}

func (v1 *v1Plugin) clone() *v1Plugin {
	if v1 == nil {
		return &v1Plugin{}
	}
	clone := *v1
	return &clone
}
