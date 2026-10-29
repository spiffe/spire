package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	node_attestor "github.com/spiffe/spire/pkg/agent/attestor/node"
	"github.com/spiffe/spire/pkg/agent/manager/storecache"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/agent/storage"
	"github.com/spiffe/spire/pkg/agent/trustbundlesources"
	"github.com/spiffe/spire/pkg/agent/workloadkey"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	serverentryv1 "github.com/spiffe/spire/pkg/server/api/entry/v1"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakeagentcatalog"
	"github.com/spiffe/spire/test/fakes/fakeagentkeymanager"
	"github.com/spiffe/spire/test/testkey"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestJWTRequestCoalescingAgentWiring(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	logger, _ := test.NewNullLogger()
	caTemplate, err := util.NewCATemplate(clock.New(), td)
	require.NoError(t, err)
	ca, caKey, err := util.SelfSign(caTemplate)
	require.NoError(t, err)

	dir := t.TempDir()
	km := fakeagentkeymanager.New(t, dir)
	agentKey, err := keymanager.ForSVID(km).GenerateKey(context.Background(), nil)
	require.NoError(t, err)
	agentTemplate, err := util.NewSVIDTemplate(clock.New(), spiffeid.RequireFromPath(td, "/spire/agent/join_token/jwt-requests").String())
	require.NoError(t, err)
	agentTemplate.PublicKey = agentKey.Public()
	agentSVID, _, err := util.Sign(agentTemplate, ca, caKey)
	require.NoError(t, err)

	serverKey := testkey.MustEC256()
	serverTemplate, err := util.NewSVIDTemplate(clock.New(), idutil.RequireServerID(td).String())
	require.NoError(t, err)
	serverTemplate.PublicKey = serverKey.Public()
	serverSVID, _, err := util.Sign(serverTemplate, ca, caKey)
	require.NoError(t, err)

	server := &jwtWiringServer{td: td, ca: ca}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			roots := x509.NewCertPool()
			roots.AddCert(ca)
			return &tls.Config{
				Certificates: []tls.Certificate{{Certificate: [][]byte{serverSVID.Raw, ca.Raw}, PrivateKey: serverKey}},
				ClientAuth:   tls.VerifyClientCertIfGiven,
				ClientCAs:    roots,
				MinVersion:   tls.VersionTLS12,
				NextProtos:   []string{"h2"},
			}, nil
		},
		MinVersion: tls.VersionTLS12,
	})))
	agentv1.RegisterAgentServer(grpcServer, server)
	entryv1.RegisterEntryServer(grpcServer, server)
	bundlev1.RegisterBundleServer(grpcServer, server)
	svidv1.RegisterSVIDServer(grpcServer, server)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveDone := make(chan error, 1)
	go func() { serveDone <- grpcServer.Serve(listener) }()
	t.Cleanup(func() {
		grpcServer.Stop()
		require.NoError(t, <-serveDone)
	})

	sto, err := storage.Open(dir)
	require.NoError(t, err)
	catalog := fakeagentcatalog.New()
	catalog.SetKeyManager(km)
	trustSources := trustbundlesources.New(&trustbundlesources.Config{TrustDomain: td.Name()}, logger)
	config := &Config{
		Log:                logger,
		TrustDomain:        td,
		ServerAddress:      listener.Addr().String(),
		WorkloadKeyType:    workloadkey.ECP256,
		RebootstrapMode:    RebootstrapNever,
		TrustBundleSources: trustSources,
	}
	metrics := &telemetry.Blackhole{}
	attestation := &node_attestor.AttestationResult{
		SVID:   []*x509.Certificate{agentSVID},
		Key:    agentKey,
		Bundle: spiffebundle.FromX509Authorities(td, []*x509.Certificate{ca}),
	}
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			field := reflect.ValueOf(config).Elem().FieldByName("JWTSVIDRequestCoalescing")
			require.True(t, field.IsValid())
			field.SetBool(enabled)
			a := New(config)
			storeCache := storecache.New(&storecache.Config{TrustDomain: td, Log: logger})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			mgr, err := a.newManager(ctx, sto, catalog, metrics, attestation, storeCache, nil)
			require.NoError(t, err)
			defer func() { stopped, stop := context.WithCancel(context.Background()); stop(); _ = mgr.Run(stopped) }()
			entry := &common.RegistrationEntry{EntryId: "jwt-entry", SpiffeId: "spiffe://example.org/workload", RevisionNumber: 1}
			one, err := mgr.FetchJWTSVID(ctx, entry, []string{"service"})
			require.NoError(t, err)
			entry.EntryId = "jwt-entry-2"
			two, err := mgr.FetchJWTSVID(ctx, entry, []string{"service"})
			require.NoError(t, err)
			if enabled {
				require.NotEqual(t, one.Token, two.Token)
			} else {
				require.Equal(t, one.Token, two.Token)
			}
		})
	}
}

type jwtWiringServer struct {
	agentv1.UnimplementedAgentServer
	entryv1.UnimplementedEntryServer
	bundlev1.UnimplementedBundleServer
	svidv1.UnimplementedSVIDServer
	td    spiffeid.TrustDomain
	ca    *x509.Certificate
	count atomic.Int32
}

func (s *jwtWiringServer) PostStatus(context.Context, *agentv1.PostStatusRequest) (*agentv1.PostStatusResponse, error) {
	return &agentv1.PostStatusResponse{}, nil
}

func (s *jwtWiringServer) GetAuthorizedEntries(context.Context, *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
	return &entryv1.GetAuthorizedEntriesResponse{Entries: []*types.Entry{
		{Id: "jwt-entry", RevisionNumber: 1, Selectors: []*types.Selector{{Type: "unix", Value: "uid:42"}}, SpiffeId: api.ProtoFromID(spiffeid.RequireFromPath(s.td, "/workload")), AdditionalAttributes: &types.Entry_AdditionalAttributes{DisableX509SvidPrefetch: true}},
		{Id: "jwt-entry-2", RevisionNumber: 1, Selectors: []*types.Selector{{Type: "unix", Value: "uid:42"}}, SpiffeId: api.ProtoFromID(spiffeid.RequireFromPath(s.td, "/workload")), AdditionalAttributes: &types.Entry_AdditionalAttributes{DisableX509SvidPrefetch: true}},
	}}, nil
}

func (s *jwtWiringServer) GetBundle(context.Context, *bundlev1.GetBundleRequest) (*types.Bundle, error) {
	return s.bundle(s.td), nil
}

func (s *jwtWiringServer) bundle(td spiffeid.TrustDomain) *types.Bundle {
	return &types.Bundle{TrustDomain: td.Name(), X509Authorities: []*types.X509Certificate{{Asn1: s.ca.Raw}}}
}

func (s *jwtWiringServer) NewJWTSVID(context.Context, *svidv1.NewJWTSVIDRequest) (*svidv1.NewJWTSVIDResponse, error) {
	enc := base64.RawURLEncoding.EncodeToString
	token := enc([]byte(`{"alg":"ES256","kid":"clean"}`)) + "." + enc(fmt.Appendf(nil, `{"serial":%d}`, s.count.Add(1))) + "." + enc(make([]byte, 64))
	now := time.Now()
	return &svidv1.NewJWTSVIDResponse{Svid: &types.JWTSVID{Token: token, Id: api.ProtoFromID(spiffeid.RequireFromPath(s.td, "/workload")), IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()}}, nil
}

func (s *jwtWiringServer) SyncAuthorizedEntries(stream entryv1.Entry_SyncAuthorizedEntriesServer) error {
	response, err := s.GetAuthorizedEntries(stream.Context(), &entryv1.GetAuthorizedEntriesRequest{})
	if err != nil {
		return err
	}
	entries := make([]api.ReadOnlyEntry, 0, len(response.Entries))
	for _, entry := range response.Entries {
		entries = append(entries, api.NewReadOnlyEntry(entry))
	}
	return serverentryv1.SyncAuthorizedEntries(stream, entries, 50)
}
