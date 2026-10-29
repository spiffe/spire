package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"reflect"
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
	commonapi "github.com/spiffe/spire/pkg/common/api"
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

func TestFederatedBundleFreshnessConfigPropagation(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	remoteTD := spiffeid.RequireTrustDomainFromString("otherdomain.test")
	logger, _ := test.NewNullLogger()
	caTemplate, err := util.NewCATemplate(clock.New(), td)
	require.NoError(t, err)
	ca, caKey, err := util.SelfSign(caTemplate)
	require.NoError(t, err)

	dir := t.TempDir()
	km := fakeagentkeymanager.New(t, dir)
	agentKey, err := keymanager.ForSVID(km).GenerateKey(context.Background(), nil)
	require.NoError(t, err)
	agentTemplate, err := util.NewSVIDTemplate(clock.New(), spiffeid.RequireFromPath(td, "/spire/agent/join_token/freshness").String())
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

	server := &freshnessConfigServer{t: t, td: td, remoteTD: remoteTD, ca: ca, caKey: caKey}
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
	for _, tc := range []struct {
		name         string
		maxStaleness time.Duration
		visibleFor   time.Duration
		expiresBy    time.Duration
	}{
		{name: "short_limit", maxStaleness: 200 * time.Millisecond, expiresBy: 700 * time.Millisecond},
		{name: "long_limit", maxStaleness: 1800 * time.Millisecond, visibleFor: time.Second, expiresBy: 4 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			field := reflect.ValueOf(config).Elem().FieldByName("FederatedBundleMaxStaleness")
			require.True(t, field.IsValid(), "Agent configuration must expose FederatedBundleMaxStaleness")
			require.Equal(t, reflect.TypeFor[time.Duration](), field.Type())
			field.SetInt(int64(tc.maxStaleness))
			a := New(config)
			storeCache := storecache.New(&storecache.Config{TrustDomain: td, Log: logger})
			mgr, err := a.newManager(context.Background(), sto, catalog, metrics, attestation, storeCache, nil)
			require.NoError(t, err)
			require.Contains(t, mgr.GetBundles(), remoteTD)

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- mgr.Run(ctx) }()
			defer func() {
				cancel()
				require.NoError(t, <-done)
			}()
			if tc.visibleFor > 0 {
				require.Never(t, func() bool {
					_, visible := mgr.GetBundles()[remoteTD]
					return !visible
				}, tc.visibleFor, 10*time.Millisecond)
			}
			require.Eventually(t, func() bool {
				_, visible := mgr.GetBundles()[remoteTD]
				return !visible
			}, tc.expiresBy, 10*time.Millisecond)
		})
	}
}

type freshnessConfigServer struct {
	agentv1.UnimplementedAgentServer
	entryv1.UnimplementedEntryServer
	bundlev1.UnimplementedBundleServer
	svidv1.UnimplementedSVIDServer
	t        *testing.T
	td       spiffeid.TrustDomain
	remoteTD spiffeid.TrustDomain
	ca       *x509.Certificate
	caKey    *ecdsa.PrivateKey
}

func (s *freshnessConfigServer) PostStatus(context.Context, *agentv1.PostStatusRequest) (*agentv1.PostStatusResponse, error) {
	return &agentv1.PostStatusResponse{}, nil
}

func (s *freshnessConfigServer) GetAuthorizedEntries(context.Context, *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
	return &entryv1.GetAuthorizedEntriesResponse{Entries: []*types.Entry{{
		Id:            "freshness-entry",
		SpiffeId:      api.ProtoFromID(spiffeid.RequireFromPath(s.td, "/workload")),
		FederatesWith: []string{s.remoteTD.Name()},
		Selectors:     api.ProtoFromSelectors([]*common.Selector{{Type: "unix", Value: "uid:1"}}),
	}}}, nil
}

func (s *freshnessConfigServer) GetBundle(context.Context, *bundlev1.GetBundleRequest) (*types.Bundle, error) {
	return s.bundle(s.td), nil
}

func (s *freshnessConfigServer) GetFederatedBundle(context.Context, *bundlev1.GetFederatedBundleRequest) (*types.Bundle, error) {
	return s.bundle(s.remoteTD), nil
}

func (s *freshnessConfigServer) bundle(td spiffeid.TrustDomain) *types.Bundle {
	return &types.Bundle{TrustDomain: td.Name(), X509Authorities: []*types.X509Certificate{{Asn1: s.ca.Raw}}}
}

func (s *freshnessConfigServer) BatchNewX509SVID(_ context.Context, req *svidv1.BatchNewX509SVIDRequest) (*svidv1.BatchNewX509SVIDResponse, error) {
	response := new(svidv1.BatchNewX509SVIDResponse)
	for _, param := range req.Params {
		csr, err := x509.ParseCertificateRequest(param.Csr)
		require.NoError(s.t, err)
		template, err := util.NewSVIDTemplate(clock.New(), spiffeid.RequireFromPath(s.td, "/workload").String())
		require.NoError(s.t, err)
		template.PublicKey = csr.PublicKey
		svid, _, err := util.Sign(template, s.ca, s.caKey)
		require.NoError(s.t, err)
		response.Results = append(response.Results, &svidv1.BatchNewX509SVIDResponse_Result{
			Status: commonapi.OK(),
			Svid:   &types.X509SVID{CertChain: [][]byte{svid.Raw}, ExpiresAt: svid.NotAfter.Unix()},
		})
	}
	return response, nil
}

func (s *freshnessConfigServer) SyncAuthorizedEntries(stream entryv1.Entry_SyncAuthorizedEntriesServer) error {
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
