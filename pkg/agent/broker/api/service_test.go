package api

import (
	"context"
	"errors"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	workloadattestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	k8sType = "type.googleapis.com/spiffe.broker.KubernetesObjectReference"
	pidType = "type.googleapis.com/spiffe.broker.PIDReference"
)

func udsContext() context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.UnixAddr{Name: "/tmp/broker.sock", Net: "unix"},
	})
}

func tcpContext() context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345},
	})
}

func ref(typeURL string) *anypb.Any {
	if typeURL == "" {
		return nil
	}
	return &anypb.Any{TypeUrl: typeURL}
}

func TestIsTCPCaller(t *testing.T) {
	assert.True(t, isTCPCaller(tcpContext()))
	assert.False(t, isTCPCaller(udsContext()))
	assert.False(t, isTCPCaller(context.Background()))
}

func TestAuthorizeReferenceType(t *testing.T) {
	caller := spiffeid.RequireFromString("spiffe://example.org/broker")
	other := spiffeid.RequireFromString("spiffe://example.org/other")

	for _, tt := range []struct {
		name       string
		byCaller   map[spiffeid.ID]ReferenceTypePolicy
		ctx        context.Context
		caller     spiffeid.ID
		ref        *anypb.Any
		expectCode codes.Code
	}{
		{
			name:       "nil reference is rejected before any gate",
			ctx:        udsContext(),
			caller:     caller,
			ref:        ref(""),
			expectCode: codes.InvalidArgument,
		},
		{
			name:       "empty type url is rejected",
			ctx:        udsContext(),
			caller:     caller,
			ref:        &anypb.Any{},
			expectCode: codes.InvalidArgument,
		},
		{
			name: "caller present and type allowed over UDS",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				Types: map[string]ReferenceTypeAccess{k8sType: {}},
			}},
			ctx:        udsContext(),
			caller:     caller,
			ref:        ref(k8sType),
			expectCode: codes.OK,
		},
		{
			name: "caller present and type not allowed",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				Types: map[string]ReferenceTypeAccess{k8sType: {}},
			}},
			ctx:        udsContext(),
			caller:     caller,
			ref:        ref(pidType),
			expectCode: codes.PermissionDenied,
		},
		{
			name: "caller absent from map behaves as wildcard over UDS",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{other: {
				Types: map[string]ReferenceTypeAccess{k8sType: {}},
			}},
			ctx:        udsContext(),
			caller:     caller,
			ref:        ref(pidType),
			expectCode: codes.OK,
		},
		{
			name: "TCP caller allowed when reference type opts in",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				Types: map[string]ReferenceTypeAccess{k8sType: {AllowOverTCP: true}},
			}},
			ctx:        tcpContext(),
			caller:     caller,
			ref:        ref(k8sType),
			expectCode: codes.OK,
		},
		{
			name: "TCP caller denied when reference type does not opt in",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				Types: map[string]ReferenceTypeAccess{k8sType: {}},
			}},
			ctx:        tcpContext(),
			caller:     caller,
			ref:        ref(k8sType),
			expectCode: codes.PermissionDenied,
		},
		{
			name:       "TCP caller denied when caller has no policy",
			ctx:        tcpContext(),
			caller:     caller,
			ref:        ref(k8sType),
			expectCode: codes.PermissionDenied,
		},
		{
			name: "wildcard allows any type over UDS",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				AllowAny: true,
			}},
			ctx:        udsContext(),
			caller:     caller,
			ref:        ref(pidType),
			expectCode: codes.OK,
		},
		{
			name: "wildcard allows any type over TCP when it opts in",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				AllowAny:        true,
				AllowAnyOverTCP: true,
			}},
			ctx:        tcpContext(),
			caller:     caller,
			ref:        ref(pidType),
			expectCode: codes.OK,
		},
		{
			name: "wildcard denies TCP by default",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				AllowAny: true,
			}},
			ctx:        tcpContext(),
			caller:     caller,
			ref:        ref(pidType),
			expectCode: codes.PermissionDenied,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := New(Config{
				AllowedReferenceTypesByCaller: tt.byCaller,
			})
			err := s.authorizeReferenceType(tt.ctx, tt.caller, tt.ref)
			if tt.expectCode == codes.OK {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tt.expectCode, status.Code(err))
		})
	}
}

func brokerCallerContext(caller spiffeid.ID) context.Context {
	spiffeURL, _ := url.Parse(caller.String())
	log, _ := test.NewNullLogger()
	ctx := rpccontext.WithLogger(context.Background(), log)
	return peer.NewContext(ctx, &peer.Peer{
		Addr:     &net.UnixAddr{Name: "/tmp/broker.sock", Net: "unix"},
		AuthInfo: credentials.TLSInfo{SPIFFEID: spiffeURL},
	})
}

var _ workloadattestor.Attestor = fakeAttestor{}

type fakeAttestor struct {
	selectors []*common.Selector
	err       error
}

func (a fakeAttestor) Attest(context.Context, int) ([]*common.Selector, error) {
	return a.selectors, a.err
}

func (a fakeAttestor) AttestReference(context.Context, *anypb.Any) ([]*common.Selector, error) {
	return a.selectors, a.err
}

type fakeManager struct {
	manager.Manager

	entries  []*common.RegistrationEntry
	jwtSVIDs map[string]*client.JWTSVID
	err      error
}

func (m *fakeManager) MatchingRegistrationEntries([]*common.Selector) []*common.RegistrationEntry {
	return m.entries
}

func (m *fakeManager) FetchJWTSVID(_ context.Context, entry *common.RegistrationEntry, _ []string) (*client.JWTSVID, error) {
	if m.err != nil {
		return nil, m.err
	}
	svid, ok := m.jwtSVIDs[entry.SpiffeId]
	if !ok {
		return nil, errors.New("no SVID for entry")
	}
	return svid, nil
}

func TestFetchJWTSVID(t *testing.T) {
	caller := spiffeid.RequireFromString("spiffe://example.org/broker")
	workloadID := "spiffe://example.org/workload"
	adminID := "spiffe://example.org/admin"
	downstreamID := "spiffe://example.org/downstream"

	jwtSVID := &client.JWTSVID{
		Token:     "jwt-token",
		IssuedAt:  time.Unix(1000, 0),
		ExpiresAt: time.Unix(2000, 0),
	}

	for _, tt := range []struct {
		name        string
		audience    []string
		attestErr   error
		fetchErr    error
		entries     []*common.RegistrationEntry
		expectCode  codes.Code
		expectSvids []*broker.JWTSVID
	}{
		{
			name:       "missing audience",
			expectCode: codes.InvalidArgument,
		},
		{
			name:       "attestation error",
			audience:   []string{"aud"},
			attestErr:  errors.New("attest failed"),
			expectCode: codes.Unauthenticated,
		},
		{
			name:     "success",
			audience: []string{"aud"},
			entries: []*common.RegistrationEntry{
				{EntryId: "1", SpiffeId: workloadID},
			},
			expectCode: codes.OK,
			expectSvids: []*broker.JWTSVID{
				{SpiffeId: workloadID, Svid: jwtSVID.Token},
			},
		},
		{
			name:     "admin entries are excluded",
			audience: []string{"aud"},
			entries: []*common.RegistrationEntry{
				{EntryId: "1", SpiffeId: adminID, Admin: true},
			},
			expectCode: codes.PermissionDenied,
		},
		{
			name:     "downstream entries are excluded",
			audience: []string{"aud"},
			entries: []*common.RegistrationEntry{
				{EntryId: "1", SpiffeId: downstreamID, Downstream: true},
			},
			expectCode: codes.PermissionDenied,
		},
		{
			name:     "admin and downstream excluded, normal entry returned",
			audience: []string{"aud"},
			entries: []*common.RegistrationEntry{
				{EntryId: "1", SpiffeId: adminID, Admin: true},
				{EntryId: "2", SpiffeId: downstreamID, Downstream: true},
				{EntryId: "3", SpiffeId: workloadID},
			},
			expectCode: codes.OK,
			expectSvids: []*broker.JWTSVID{
				{SpiffeId: workloadID, Svid: jwtSVID.Token},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := New(Config{
				Manager: &fakeManager{
					entries: tt.entries,
					jwtSVIDs: map[string]*client.JWTSVID{
						workloadID: jwtSVID,
					},
					err: tt.fetchErr,
				},
				Attestor: fakeAttestor{err: tt.attestErr},
			})

			resp, err := s.FetchJWTSVID(brokerCallerContext(caller), &broker.FetchJWTSVIDRequest{
				Audience:  tt.audience,
				Reference: &broker.WorkloadReference{Reference: ref(k8sType)},
			})

			if tt.expectCode != codes.OK {
				require.Error(t, err)
				assert.Equal(t, tt.expectCode, status.Code(err))
				assert.Nil(t, resp)
				return
			}

			require.NoError(t, err)
			require.Len(t, resp.Svids, len(tt.expectSvids))
			for i, want := range tt.expectSvids {
				assert.Equal(t, want.SpiffeId, resp.Svids[i].SpiffeId)
				assert.Equal(t, want.Svid, resp.Svids[i].Svid)
			}
		})
	}
}
