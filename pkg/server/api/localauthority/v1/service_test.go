package localauthority_test

import (
	"context"
	"crypto"
	"errors"
	"testing"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api/localauthority/v1"
	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/ca/manager"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	testutil "github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

var (
	ctx               = context.Background()
	serverTrustDomain = spiffeid.RequireTrustDomainFromString("example.org")
	keyA              = testkey.MustEC256()
	keyB              = testkey.MustEC256()
	keyABytes, _      = x509util.GetSubjectKeyID(keyA.Public())
	keyBBytes, _      = x509util.GetSubjectKeyID(keyB.Public())
	authorityIDKeyA   = x509util.SubjectKeyIDToString(keyABytes)
	authorityIDKeyB   = x509util.SubjectKeyIDToString(keyBBytes)
)

func TestGetX509AuthorityState(t *testing.T) {
	for _, tt := range []struct {
		name        string
		currentSlot *fakeSlot
		nextSlot    *fakeSlot
		expectLogs  []spiretest.LogEntry
		expectCode  codes.Code
		expectMsg   string
		expectResp  *localauthorityv1.GetX509AuthorityStateResponse
	}{
		{
			name:        "current is set",
			currentSlot: createSlot(true, authorityIDKeyA),
			nextSlot:    &fakeSlot{},
			expectResp: &localauthorityv1.GetX509AuthorityStateResponse{
				States: []*localauthorityv1.AuthorityState{
					{
						AuthorityId: authorityIDKeyA,
						Status:      localauthorityv1.AuthorityState_ACTIVE,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
				},
			},
		},
		{
			name:        "next is set",
			currentSlot: &fakeSlot{},
			nextSlot:    createSlot(true, authorityIDKeyB),
			expectResp: &localauthorityv1.GetX509AuthorityStateResponse{
				States: []*localauthorityv1.AuthorityState{
					{
						AuthorityId: authorityIDKeyB,
						Status:      localauthorityv1.AuthorityState_PREPARED,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
				},
			},
		},
		{
			name:        "next contains an old authority",
			currentSlot: createSlot(true, authorityIDKeyA),
			nextSlot:    createSlot(false, authorityIDKeyB),
			expectResp: &localauthorityv1.GetX509AuthorityStateResponse{
				States: []*localauthorityv1.AuthorityState{
					{
						AuthorityId: authorityIDKeyA,
						Status:      localauthorityv1.AuthorityState_ACTIVE,
					},
					{
						AuthorityId: authorityIDKeyB,
						Status:      localauthorityv1.AuthorityState_OLD,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
				},
			},
		},
		{
			name:        "current slot has no public key",
			currentSlot: createSlot(true, ""),
			nextSlot:    &fakeSlot{},
			expectCode:  codes.Internal,
			expectMsg:   "current slot does not contains authority ID",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Current slot does not contains authority ID",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "current slot does not contains authority ID",
						telemetry.Type:          "audit",
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t)
			defer test.Cleanup()

			test.ca.currentX509CASlot = tt.currentSlot
			test.ca.nextX509CASlot = tt.nextSlot

			resp, err := test.client.GetX509AuthorityState(ctx, &localauthorityv1.GetX509AuthorityStateRequest{})

			spiretest.AssertGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			spiretest.AssertProtoEqual(t, tt.expectResp, resp)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
		})
	}
}

func TestPrepareX509Authority(t *testing.T) {
	for _, tt := range []struct {
		name        string
		currentSlot *fakeSlot
		prepareErr  error
		nextSlot    *fakeSlot
		expectLogs  []spiretest.LogEntry
		expectCode  codes.Code
		expectMsg   string
		expectResp  *localauthorityv1.PrepareX509AuthorityResponse
	}{
		{
			name:     "using next to prepare",
			nextSlot: createSlot(true, authorityIDKeyB),
			expectResp: &localauthorityv1.PrepareX509AuthorityResponse{
				PreparedAuthority: &localauthorityv1.AuthorityState{
					Status:      localauthorityv1.AuthorityState_PREPARED,
					AuthorityId: authorityIDKeyB,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
				},
			},
		},
		{
			name:        "using current to prepare",
			currentSlot: createSlot(true, authorityIDKeyA),
			nextSlot:    createSlot(false, authorityIDKeyB),
			expectResp: &localauthorityv1.PrepareX509AuthorityResponse{
				PreparedAuthority: &localauthorityv1.AuthorityState{
					Status:      localauthorityv1.AuthorityState_PREPARED,
					AuthorityId: authorityIDKeyA,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
				},
			},
		},
		{
			name:       "failed to prepare",
			nextSlot:   createSlot(true, authorityIDKeyB),
			prepareErr: errors.New("oh no"),
			expectCode: codes.Internal,
			expectMsg:  "failed to prepare X.509 authority: oh no",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to prepare X.509 authority",
					Data: logrus.Fields{
						logrus.ErrorKey: "oh no",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to prepare X.509 authority: oh no",
						telemetry.Type:          "audit",
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t)
			defer test.Cleanup()

			test.ca.currentX509CASlot = tt.currentSlot
			test.ca.nextX509CASlot = tt.nextSlot
			test.ca.prepareX509CAErr = tt.prepareErr

			resp, err := test.client.PrepareX509Authority(ctx, &localauthorityv1.PrepareX509AuthorityRequest{})

			spiretest.AssertGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			spiretest.AssertProtoEqual(t, tt.expectResp, resp)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
		})
	}
}

func TestActivateX509Authority(t *testing.T) {
	for _, tt := range []struct {
		name        string
		currentSlot *fakeSlot
		nextSlot    *fakeSlot

		rotateCalled  bool
		keyToActivate string
		expectLogs    []spiretest.LogEntry
		expectCode    codes.Code
		expectMsg     string
		expectResp    *localauthorityv1.ActivateX509AuthorityResponse
	}{
		{
			name:         "activate successfully",
			currentSlot:  createSlot(true, authorityIDKeyA),
			nextSlot:     createSlot(true, authorityIDKeyB),
			rotateCalled: true,
			expectResp: &localauthorityv1.ActivateX509AuthorityResponse{
				ActivatedAuthority: &localauthorityv1.AuthorityState{
					Status:      localauthorityv1.AuthorityState_ACTIVE,
					AuthorityId: authorityIDKeyA,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
				},
			},
		},
		{
			name:          "activate an old authority",
			currentSlot:   createSlot(true, authorityIDKeyA),
			nextSlot:      createSlot(true, authorityIDKeyB),
			keyToActivate: authorityIDKeyA,
			expectCode:    codes.InvalidArgument,
			expectMsg:     "activating an old authority is not supported yet",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: activating an old authority is not supported yet",
					Data: logrus.Fields{
						telemetry.LocalAuthorityID: authorityIDKeyA,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: authorityIDKeyA,
						telemetry.StatusCode:       "InvalidArgument",
						telemetry.StatusMessage:    "activating an old authority is not supported yet",
					},
				},
			},
		},
		{
			name:        "next slot is not set",
			currentSlot: createSlot(true, authorityIDKeyA),
			nextSlot:    &fakeSlot{},
			expectCode:  codes.Internal,
			expectMsg:   "no prepared authority found",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "No prepared authority found",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "no prepared authority found",
						telemetry.Type:          "audit",
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t)
			defer test.Cleanup()

			test.ca.currentX509CASlot = tt.currentSlot
			test.ca.nextX509CASlot = tt.nextSlot

			resp, err := test.client.ActivateX509Authority(ctx, &localauthorityv1.ActivateX509AuthorityRequest{
				AuthorityId: tt.keyToActivate,
			})

			require.Equal(t, tt.rotateCalled, test.ca.rotateX509CACalled)
			spiretest.AssertGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			spiretest.AssertProtoEqual(t, tt.expectResp, resp)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
		})
	}
}

func TestTaintX509Authority(t *testing.T) {
	clk := clock.New()
	template, err := testutil.NewCATemplate(clk, serverTrustDomain)
	require.NoError(t, err)

	currentCA, currentKey, err := testutil.SelfSign(template)
	require.NoError(t, err)
	currentKeySKI, err := x509util.GetSubjectKeyID(currentKey.Public())
	require.NoError(t, err)
	currentAuthorityID := x509util.SubjectKeyIDToString(currentKeySKI)

	nextCA, nextKey, err := testutil.SelfSign(template)
	require.NoError(t, err)
	nextKeySKI, err := x509util.GetSubjectKeyID(nextKey.Public())
	require.NoError(t, err)
	nextAuthorityID := x509util.SubjectKeyIDToString(nextKeySKI)

	oldCA, oldKey, err := testutil.SelfSign(template)
	require.NoError(t, err)
	oldKeySKI, err := x509util.GetSubjectKeyID(oldKey.Public())
	require.NoError(t, err)
	oldAuthorityID := x509util.SubjectKeyIDToString(oldKeySKI)

	for _, tt := range []struct {
		name        string
		currentSlot *fakeSlot
		nextSlot    *fakeSlot
		keyToTaint  string

		expectKeyToTaint crypto.PublicKey
		expectLogs       []spiretest.LogEntry
		expectCode       codes.Code
		expectMsg        string
		expectResp       *localauthorityv1.TaintX509AuthorityResponse
	}{
		{
			name:        "taint old authority",
			currentSlot: createSlot(true, currentAuthorityID),
			nextSlot:    createSlot(false, nextAuthorityID),
			expectResp: &localauthorityv1.TaintX509AuthorityResponse{
				TaintedAuthority: &localauthorityv1.AuthorityState{
					Status:      localauthorityv1.AuthorityState_OLD,
					AuthorityId: nextAuthorityID,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "X.509 authority tainted successfully",
					Data: logrus.Fields{
						telemetry.LocalAuthorityID: nextAuthorityID,
					},
				},
			},
		},
		{
			name:        "taint authority from parameter",
			currentSlot: createSlot(true, currentAuthorityID),
			nextSlot:    createSlot(false, nextAuthorityID),
			keyToTaint:  oldAuthorityID,
			expectResp: &localauthorityv1.TaintX509AuthorityResponse{
				TaintedAuthority: &localauthorityv1.AuthorityState{
					Status:      localauthorityv1.AuthorityState_OLD,
					AuthorityId: oldAuthorityID,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "success",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: oldAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "X.509 authority tainted successfully",
					Data: logrus.Fields{
						telemetry.LocalAuthorityID: oldAuthorityID,
					},
				},
			},
		},
		{
			name:        "no allow to taint a prepared key",
			currentSlot: createSlot(true, currentAuthorityID),
			nextSlot:    createSlot(true, nextAuthorityID),
			expectCode:  codes.InvalidArgument,
			expectMsg:   "invalid authority ID: unable to use a prepared key",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid authority ID",
					Data: logrus.Fields{
						logrus.ErrorKey: "unable to use a prepared key",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "invalid authority ID: unable to use a prepared key",
						telemetry.Type:          "audit",
					},
				},
			},
		},
		{
			name:        "unable to taint current key",
			currentSlot: createSlot(true, currentAuthorityID),
			nextSlot:    createSlot(false, nextAuthorityID),
			keyToTaint:  currentAuthorityID,
			expectCode:  codes.InvalidArgument,
			expectMsg:   "invalid authority ID: unable to use current authority",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid authority ID",
					Data: logrus.Fields{
						logrus.ErrorKey: "unable to use current authority",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "InvalidArgument",
						telemetry.StatusMessage:    "invalid authority ID: unable to use current authority",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: currentAuthorityID,
					},
				},
			},
		},
		{
			name:        "ds fails to taint",
			currentSlot: createSlot(true, currentAuthorityID),
			nextSlot:    createSlot(false, nextAuthorityID),
			keyToTaint:  authorityIDKeyA,
			expectCode:  codes.Internal,
			expectMsg:   "failed to taint X.509 authority: no root CA found with provided Subject Key ID",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to taint X.509 authority",
					Data: logrus.Fields{
						logrus.ErrorKey:            "rpc error: code = NotFound desc = no root CA found with provided Subject Key ID",
						telemetry.LocalAuthorityID: authorityIDKeyA,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "Internal",
						telemetry.StatusMessage:    "failed to taint X.509 authority: no root CA found with provided Subject Key ID",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: authorityIDKeyA,
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t)
			defer test.Cleanup()

			test.ca.currentX509CASlot = tt.currentSlot
			test.ca.nextX509CASlot = tt.nextSlot
			_, err := test.ds.CreateBundle(ctx, &common.Bundle{
				TrustDomainId: serverTrustDomain.IDString(),
				RootCas: []*common.Certificate{
					{
						DerBytes: currentCA.Raw,
					},
					{
						DerBytes: nextCA.Raw,
					},
					{
						DerBytes: oldCA.Raw,
					},
				},
			})
			require.NoError(t, err)

			resp, err := test.client.TaintX509Authority(ctx, &localauthorityv1.TaintX509AuthorityRequest{
				AuthorityId: tt.keyToTaint,
			})

			spiretest.AssertGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsg)
			spiretest.AssertProtoEqual(t, tt.expectResp, resp)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
		})
	}
}

func TestRevokeX509Authority(t *testing.T) {
	clk := clock.New()
	template, err := testutil.NewCATemplate(clk, serverTrustDomain)
	require.NoError(t, err)

	currentCA, currentKey, err := testutil.SelfSign(template)
	require.NoError(t, err)
	currentKeySKI, err := x509util.GetSubjectKeyID(currentKey.Public())
	require.NoError(t, err)
	currentAuthorityID := x509util.SubjectKeyIDToString(currentKeySKI)

	nextCA, nextKey, err := testutil.SelfSign(template)
	require.NoError(t, err)
	nextKeySKI, err := x509util.GetSubjectKeyID(nextKey.Public())
	require.NoError(t, err)
	nextAuthorityID := x509util.SubjectKeyIDToString(nextKeySKI)

	oldCA, oldKey, err := testutil.SelfSign(template)
	require.NoError(t, err)
	oldKeySKI, err := x509util.GetSubjectKeyID(oldKey.Public())
	require.NoError(t, err)
	oldAuthorityID := x509util.SubjectKeyIDToString(oldKeySKI)

	for _, tt := range []struct {
		name        string
		currentSlot *fakeSlot
		nextSlot    *fakeSlot
		keyToRevoke string

		expectKeyToTaint crypto.PublicKey
		expectLogs       []spiretest.LogEntry
		expectCode       codes.Code
		expectMsg        string
		expectResp       *localauthorityv1.RevokeX509AuthorityResponse
	}{
		{
			name:        "revoke old authority",
			currentSlot: createSlot(true, currentAuthorityID),
			nextSlot:    createSlot(false, nextAuthorityID),
			expectResp: &localauthorityv1.RevokeX509AuthorityResponse{
				RevokedAuthority: &localauthorityv1.AuthorityState{
					Status:      localauthorityv1.AuthorityState_OLD,
					AuthorityId: nextAuthorityID,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "X.509 authority revoked successfully",
					Data: logrus.Fields{
						telemetry.LocalAuthorityID: nextAuthorityID,
					},
				},
			},
		},
		{
			name:        "revoke authority from parameter",
			currentSlot: createSlot(true, currentAuthorityID),
			nextSlot:    createSlot(false, nextAuthorityID),
			keyToRevoke: oldAuthorityID,
			expectResp: &localauthorityv1.RevokeX509AuthorityResponse{
				RevokedAuthority: &localauthorityv1.AuthorityState{
					Status:      localauthorityv1.AuthorityState_OLD,
					AuthorityId: oldAuthorityID,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "success",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: oldAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "X.509 authority revoked successfully",
					Data: logrus.Fields{
						telemetry.LocalAuthorityID: oldAuthorityID,
					},
				},
			},
		},
		{
			name:        "no allow to revoke a prepared key",
			currentSlot: createSlot(true, currentAuthorityID),
			nextSlot:    createSlot(true, nextAuthorityID),
			expectCode:  codes.InvalidArgument,
			expectMsg:   "invalid authority ID: unable to use a prepared key",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid authority ID",
					Data: logrus.Fields{
						logrus.ErrorKey: "unable to use a prepared key",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "invalid authority ID: unable to use a prepared key",
						telemetry.Type:          "audit",
					},
				},
			},
		},
		{
			name:        "unable to revoke current key",
			currentSlot: createSlot(true, currentAuthorityID),
			nextSlot:    createSlot(false, nextAuthorityID),
			keyToRevoke: currentAuthorityID,
			expectCode:  codes.InvalidArgument,
			expectMsg:   "invalid authority ID: unable to use current authority",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid authority ID",
					Data: logrus.Fields{
						logrus.ErrorKey: "unable to use current authority",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "InvalidArgument",
						telemetry.StatusMessage:    "invalid authority ID: unable to use current authority",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: currentAuthorityID,
					},
				},
			},
		},
		{
			name:        "ds fails to revoke",
			currentSlot: createSlot(true, currentAuthorityID),
			nextSlot:    createSlot(false, nextAuthorityID),
			keyToRevoke: authorityIDKeyA,
			expectCode:  codes.Internal,
			expectMsg:   "failed to revoke X.509 authority: no root CA found with provided Subject Key ID",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to revoke X.509 authority",
					Data: logrus.Fields{
						logrus.ErrorKey:            "rpc error: code = NotFound desc = no root CA found with provided Subject Key ID",
						telemetry.LocalAuthorityID: authorityIDKeyA,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "Internal",
						telemetry.StatusMessage:    "failed to revoke X.509 authority: no root CA found with provided Subject Key ID",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: authorityIDKeyA,
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t)
			defer test.Cleanup()

			test.ca.currentX509CASlot = tt.currentSlot
			test.ca.nextX509CASlot = tt.nextSlot
			_, err := test.ds.CreateBundle(ctx, &common.Bundle{
				TrustDomainId: serverTrustDomain.IDString(),
				RootCas: []*common.Certificate{
					{
						DerBytes: currentCA.Raw,
					},
					{
						DerBytes:   nextCA.Raw,
						TaintedKey: true,
					},
					{
						DerBytes:   oldCA.Raw,
						TaintedKey: true,
					},
				},
			})
			require.NoError(t, err)

			resp, err := test.client.RevokeX509Authority(ctx, &localauthorityv1.RevokeX509AuthorityRequest{
				AuthorityId: tt.keyToRevoke,
			})

			spiretest.AssertGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsg)
			spiretest.AssertProtoEqual(t, tt.expectResp, resp)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
		})
	}
}

func setupServiceTest(t *testing.T) *serviceTest {
	ds := fakedatastore.New(t)
	m := &fakeCAManager{}

	service := localauthority.New(localauthority.Config{
		TrustDomain: serverTrustDomain,
		DataStore:   ds,
		CAManager:   m,
	})

	log, logHook := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	registerFn := func(s *grpc.Server) {
		localauthorityv1.RegisterLocalAuthorityServer(s, service)
	}

	test := &serviceTest{
		ds:      ds,
		logHook: logHook,
		ca:      m,
	}

	ppMiddleware := middleware.Preprocess(func(ctx context.Context, fullMethod string, req interface{}) (context.Context, error) {
		ctx = rpccontext.WithLogger(ctx, log)
		return ctx, nil
	})

	unaryInterceptor, streamInterceptor := middleware.Interceptors(middleware.Chain(
		ppMiddleware,
		// Add audit log with local tracking disabled
		middleware.WithAuditLog(false),
	))
	server := grpc.NewServer(
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
	)
	conn, done := spiretest.NewAPIServerWithMiddleware(t, registerFn, server)
	test.done = done
	test.client = localauthorityv1.NewLocalAuthorityClient(conn)

	return test
}

type serviceTest struct {
	client  localauthorityv1.LocalAuthorityClient
	done    func()
	ds      *fakedatastore.DataStore
	logHook *test.Hook
	ca      *fakeCAManager
}

func (s *serviceTest) Cleanup() {
	s.done()
}

type fakeCAManager struct {
	currentX509CASlot  *fakeSlot
	nextX509CASlot     *fakeSlot
	rotateX509CACalled bool

	currentJWTKeySlot *fakeSlot
	nextJWTKeySlot    *fakeSlot

	prepareJWTKeyErr error

	prepareX509CAErr error
}

func (m *fakeCAManager) GetCurrentJWTKeySlot() manager.Slot {
	return m.currentJWTKeySlot
}

func (m *fakeCAManager) GetNextJWTKeySlot() manager.Slot {
	return m.nextJWTKeySlot
}

func (m *fakeCAManager) PrepareJWTKey(ctx context.Context) error {
	return m.prepareJWTKeyErr
}

func (m *fakeCAManager) RotateJWTKey() {}

func (m *fakeCAManager) GetCurrentX509CASlot() manager.Slot {
	return m.currentX509CASlot
}

func (m *fakeCAManager) GetNextX509CASlot() manager.Slot {
	return m.nextX509CASlot
}

func (m *fakeCAManager) PrepareX509CA(ctx context.Context) error {
	return m.prepareX509CAErr
}

func (m *fakeCAManager) RotateX509CA() {
	m.rotateX509CACalled = true
}

type fakeSlot struct {
	manager.Slot

	hasValue    bool
	authorityID string
}

func (s *fakeSlot) IsEmpty() bool {
	return !s.hasValue
}

func (s *fakeSlot) AuthorityID() string {
	return s.authorityID
}

func createSlot(hasValue bool, authorityID string) *fakeSlot {
	return &fakeSlot{
		hasValue:    hasValue,
		authorityID: authorityID,
	}
}
