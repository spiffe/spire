package localauthority_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"testing"
	"time"

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
	"github.com/spiffe/spire/proto/private/server/journal"
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
	notAfterCurrent   = time.Now().Add(time.Minute)
	notAfterNext      = notAfterCurrent.Add(time.Minute)
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
			currentSlot: createSlot(journal.Status_ACTIVE, authorityIDKeyA, keyA.Public(), notAfterCurrent),
			nextSlot:    &fakeSlot{},
			expectResp: &localauthorityv1.GetX509AuthorityStateResponse{
				Active: &localauthorityv1.AuthorityState{
					AuthorityId: authorityIDKeyA,
					ExpiresAt:   notAfterCurrent.Unix(),
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
			name:        "no current slot is set",
			currentSlot: &fakeSlot{},
			nextSlot:    createSlot(journal.Status_UNKNOWN, authorityIDKeyB, keyB.Public(), notAfterNext),
			expectCode:  codes.Unavailable,
			expectMsg:   "server is initializing",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Server is initializing",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "Unavailable",
						telemetry.StatusMessage: "server is initializing",
					},
				},
			},
		},
		{
			name:        "next contains an old authority",
			currentSlot: createSlot(journal.Status_ACTIVE, authorityIDKeyA, keyA.Public(), notAfterCurrent),
			nextSlot:    createSlot(journal.Status_OLD, authorityIDKeyB, keyB.Public(), notAfterNext),
			expectResp: &localauthorityv1.GetX509AuthorityStateResponse{
				Active: &localauthorityv1.AuthorityState{
					AuthorityId: authorityIDKeyA,
					ExpiresAt:   notAfterCurrent.Unix(),
				},
				Old: &localauthorityv1.AuthorityState{
					AuthorityId: authorityIDKeyB,
					ExpiresAt:   notAfterNext.Unix(),
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
			currentSlot: createSlot(journal.Status_ACTIVE, "", nil, time.Time{}),
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
			name:        "using next to prepare",
			currentSlot: createSlot(journal.Status_ACTIVE, authorityIDKeyA, keyA.Public(), notAfterCurrent),
			nextSlot:    createSlot(journal.Status_OLD, authorityIDKeyB, keyB.Public(), notAfterNext),
			expectResp: &localauthorityv1.PrepareX509AuthorityResponse{
				PreparedAuthority: &localauthorityv1.AuthorityState{
					AuthorityId: authorityIDKeyB,
					ExpiresAt:   notAfterNext.Unix(),
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
			name:        "current slot is not initialized",
			currentSlot: createSlot(journal.Status_OLD, authorityIDKeyA, keyA.Public(), notAfterCurrent),
			nextSlot:    createSlot(journal.Status_PREPARED, authorityIDKeyB, keyB.Public(), notAfterNext),
			expectCode:  codes.Unavailable,
			expectMsg:   "server is initializing",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Server is initializing",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "Unavailable",
						telemetry.StatusMessage: "server is initializing",
					},
				},
			},
		},
		{
			name:        "failed to prepare",
			currentSlot: createSlot(journal.Status_ACTIVE, authorityIDKeyA, keyA.Public(), notAfterCurrent),
			nextSlot:    createSlot(journal.Status_PREPARED, authorityIDKeyB, keyB.Public(), notAfterNext),
			prepareErr:  errors.New("oh no"),
			expectCode:  codes.Internal,
			expectMsg:   "failed to prepare X.509 authority: oh no",
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
			name:          "activate successfully",
			currentSlot:   createSlot(journal.Status_ACTIVE, authorityIDKeyA, keyA.Public(), notAfterCurrent),
			nextSlot:      createSlot(journal.Status_PREPARED, authorityIDKeyB, keyB.Public(), notAfterNext),
			keyToActivate: authorityIDKeyB,
			rotateCalled:  true,
			expectResp: &localauthorityv1.ActivateX509AuthorityResponse{
				ActivatedAuthority: &localauthorityv1.AuthorityState{
					AuthorityId: authorityIDKeyA,
					ExpiresAt:   notAfterCurrent.Unix(),
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "success",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: authorityIDKeyB,
					},
				},
			},
		},
		{
			name:          "activate invalid authority ID",
			currentSlot:   createSlot(journal.Status_OLD, authorityIDKeyA, keyA.Public(), notAfterCurrent),
			nextSlot:      createSlot(journal.Status_OLD, authorityIDKeyB, keyB.Public(), notAfterNext),
			keyToActivate: authorityIDKeyA,
			expectCode:    codes.InvalidArgument,
			expectMsg:     "unexpected authority ID",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: unexpected authority ID",
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
						telemetry.StatusMessage:    "unexpected authority ID",
					},
				},
			},
		},
		{
			name:          "next slot is not set",
			currentSlot:   createSlot(journal.Status_ACTIVE, authorityIDKeyA, keyA.Public(), notAfterCurrent),
			nextSlot:      createSlot(journal.Status_OLD, authorityIDKeyB, keyB.Public(), notAfterNext),
			keyToActivate: authorityIDKeyB,
			expectCode:    codes.Internal,
			expectMsg:     "only Prepared authorities can be activated",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Only Prepared authorities can be activated",
					Data: logrus.Fields{
						telemetry.LocalAuthorityID: authorityIDKeyB,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "Internal",
						telemetry.StatusMessage:    "only Prepared authorities can be activated",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: authorityIDKeyB,
					},
				},
			},
		},
		{
			name:        "no authority ID provided",
			currentSlot: createSlot(journal.Status_ACTIVE, authorityIDKeyA, keyA.Public(), notAfterCurrent),
			nextSlot:    createSlot(journal.Status_PREPARED, authorityIDKeyB, keyB.Public(), notAfterNext),
			expectCode:  codes.InvalidArgument,
			expectMsg:   "no authority ID provided",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: no authority ID provided",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "no authority ID provided",
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
	nextPublicKeyRaw, err := x509.MarshalPKIXPublicKey(nextKey.Public())
	require.NoError(t, err)
	nextKeySKI, err := x509util.GetSubjectKeyID(nextKey.Public())
	require.NoError(t, err)
	nextAuthorityID := x509util.SubjectKeyIDToString(nextKeySKI)

	oldCA, _, err := testutil.SelfSign(template)
	require.NoError(t, err)

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
		taintedKey       []byte
	}{
		{
			name:        "taint old authority",
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), notAfterCurrent),
			nextSlot:    createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), notAfterNext),
			keyToTaint:  nextAuthorityID,
			expectResp: &localauthorityv1.TaintX509AuthorityResponse{
				TaintedAuthority: &localauthorityv1.AuthorityState{
					AuthorityId: nextAuthorityID,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "success",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: nextAuthorityID,
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
			name:        "no authority ID provided",
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), notAfterCurrent),
			nextSlot:    createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), notAfterNext),
			expectCode:  codes.InvalidArgument,
			expectMsg:   "no authority ID provided",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: no authority ID provided",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "no authority ID provided",
						telemetry.Type:          "audit",
					},
				},
			},
		},
		{
			name:        "no allow to taint a prepared key",
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), notAfterCurrent),
			nextSlot:    createSlot(journal.Status_PREPARED, nextAuthorityID, nextKey.Public(), notAfterNext),
			keyToTaint:  nextAuthorityID,
			expectCode:  codes.InvalidArgument,
			expectMsg:   "only Old local authorities can be tainted",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: only Old local authorities can be tainted",
					Data: logrus.Fields{
						telemetry.LocalAuthorityID: nextAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "InvalidArgument",
						telemetry.StatusMessage:    "only Old local authorities can be tainted",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: nextAuthorityID,
					},
				},
			},
		},
		{
			name:        "unable to taint current key",
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), notAfterCurrent),
			nextSlot:    createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), notAfterNext),
			keyToTaint:  currentAuthorityID,
			expectCode:  codes.InvalidArgument,
			expectMsg:   "unable to taint current local authority",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: unable to taint current local authority",
					Data: logrus.Fields{
						telemetry.LocalAuthorityID: currentAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "InvalidArgument",
						telemetry.StatusMessage:    "unable to taint current local authority",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: currentAuthorityID,
					},
				},
			},
		},
		{
			name:        "authority ID not found",
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), notAfterCurrent),
			nextSlot:    createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), notAfterNext),
			keyToTaint:  authorityIDKeyA,
			expectCode:  codes.InvalidArgument,
			expectMsg:   "unexpected authority ID",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: unexpected authority ID",
					Data: logrus.Fields{
						telemetry.LocalAuthorityID: authorityIDKeyA,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "InvalidArgument",
						telemetry.StatusMessage:    "unexpected authority ID",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: authorityIDKeyA,
					},
				},
			},
		},
		{
			name:        "failed to taint already tainted key",
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), notAfterCurrent),
			nextSlot:    createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), notAfterNext),
			keyToTaint:  nextAuthorityID,
			taintedKey:  nextPublicKeyRaw,
			expectCode:  codes.Internal,
			expectMsg:   "failed to taint X.509 authority: root CA is already tainted",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to taint X.509 authority",
					Data: logrus.Fields{
						logrus.ErrorKey:            "rpc error: code = InvalidArgument desc = root CA is already tainted",
						telemetry.LocalAuthorityID: nextAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "Internal",
						telemetry.StatusMessage:    "failed to taint X.509 authority: root CA is already tainted",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: nextAuthorityID,
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t)
			defer test.Cleanup()

			var taintedKeys []*common.X509TaintedKey
			if tt.taintedKey != nil {
				taintedKeys = append(taintedKeys, &common.X509TaintedKey{PublicKey: tt.taintedKey})
			}

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
				X509TaintedKeys: taintedKeys,
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
	nextPublicKeyRaw, err := x509.MarshalPKIXPublicKey(nextKey.Public())
	require.NoError(t, err)
	nextKeySKI, err := x509util.GetSubjectKeyID(nextKey.Public())
	require.NoError(t, err)
	nextAuthorityID := x509util.SubjectKeyIDToString(nextKeySKI)

	oldCA, oldKey, err := testutil.SelfSign(template)
	require.NoError(t, err)
	oldPublicKeyRaw, err := x509.MarshalPKIXPublicKey(oldKey.Public())
	require.NoError(t, err)
	oldKeySKI, err := x509util.GetSubjectKeyID(oldKey.Public())
	require.NoError(t, err)
	oldAuthorityID := x509util.SubjectKeyIDToString(oldKeySKI)

	for _, tt := range []struct {
		name          string
		currentSlot   *fakeSlot
		nextSlot      *fakeSlot
		keyToRevoke   string
		noTaintedKeys bool

		expectKeyToTaint crypto.PublicKey
		expectLogs       []spiretest.LogEntry
		expectCode       codes.Code
		expectMsg        string
		expectResp       *localauthorityv1.RevokeX509AuthorityResponse
	}{
		{
			name:        "revoke authority from parameter",
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), notAfterCurrent),
			nextSlot:    createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), notAfterNext),
			keyToRevoke: oldAuthorityID,
			expectResp: &localauthorityv1.RevokeX509AuthorityResponse{
				RevokedAuthority: &localauthorityv1.AuthorityState{
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
			name:        "no authority ID provided",
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), notAfterCurrent),
			nextSlot:    createSlot(journal.Status_PREPARED, nextAuthorityID, nextKey.Public(), notAfterNext),
			expectCode:  codes.InvalidArgument,
			expectMsg:   "invalid authority ID: no authority ID provided",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid authority ID",
					Data: logrus.Fields{
						logrus.ErrorKey: "no authority ID provided",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "invalid authority ID: no authority ID provided",
						telemetry.Type:          "audit",
					},
				},
			},
		},
		{
			name:        "no allow to revoke a prepared key",
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), notAfterCurrent),
			nextSlot:    createSlot(journal.Status_PREPARED, nextAuthorityID, nextKey.Public(), notAfterNext),
			keyToRevoke: nextAuthorityID,
			expectCode:  codes.InvalidArgument,
			expectMsg:   "invalid authority ID: unable to use a prepared key",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid authority ID",
					Data: logrus.Fields{
						logrus.ErrorKey:            "unable to use a prepared key",
						telemetry.LocalAuthorityID: nextAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "InvalidArgument",
						telemetry.StatusMessage:    "invalid authority ID: unable to use a prepared key",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: nextAuthorityID,
					},
				},
			},
		},
		{
			name:        "unable to revoke current key",
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), notAfterCurrent),
			nextSlot:    createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), notAfterNext),
			keyToRevoke: currentAuthorityID,
			expectCode:  codes.InvalidArgument,
			expectMsg:   "invalid authority ID: unable to use current authority",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid authority ID",
					Data: logrus.Fields{
						logrus.ErrorKey:            "unable to use current authority",
						telemetry.LocalAuthorityID: currentAuthorityID,
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
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), notAfterCurrent),
			nextSlot:    createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), notAfterNext),
			keyToRevoke: authorityIDKeyA,
			expectCode:  codes.InvalidArgument,
			expectMsg:   "invalid authority ID: no ca found with provided authority ID",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid authority ID",
					Data: logrus.Fields{
						logrus.ErrorKey:            "no ca found with provided authority ID",
						telemetry.LocalAuthorityID: authorityIDKeyA,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "InvalidArgument",
						telemetry.StatusMessage:    "invalid authority ID: no ca found with provided authority ID",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: authorityIDKeyA,
					},
				},
			},
		},
		{
			name:          "failed to revoke untainted key",
			currentSlot:   createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), notAfterCurrent),
			nextSlot:      createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), notAfterNext),
			keyToRevoke:   nextAuthorityID,
			noTaintedKeys: true,
			expectCode:    codes.Internal,
			expectMsg:     "failed to revoke X.509 authority: it is not possible to revoke an untainted root CA",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to revoke X.509 authority",
					Data: logrus.Fields{
						logrus.ErrorKey:            "rpc error: code = InvalidArgument desc = it is not possible to revoke an untainted root CA",
						telemetry.LocalAuthorityID: nextAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "Internal",
						telemetry.StatusMessage:    "failed to revoke X.509 authority: it is not possible to revoke an untainted root CA",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: nextAuthorityID,
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

			var taintedKeys []*common.X509TaintedKey
			if !tt.noTaintedKeys {
				taintedKeys = []*common.X509TaintedKey{
					{PublicKey: nextPublicKeyRaw},
					{PublicKey: oldPublicKeyRaw},
				}
			}

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
				X509TaintedKeys: taintedKeys,
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

func (m *fakeCAManager) PrepareJWTKey(context.Context) error {
	return m.prepareJWTKeyErr
}

func (m *fakeCAManager) RotateJWTKey() {}

func (m *fakeCAManager) GetCurrentX509CASlot() manager.Slot {
	return m.currentX509CASlot
}

func (m *fakeCAManager) GetNextX509CASlot() manager.Slot {
	return m.nextX509CASlot
}

func (m *fakeCAManager) PrepareX509CA(context.Context) error {
	return m.prepareX509CAErr
}

func (m *fakeCAManager) RotateX509CA() {
	m.rotateX509CACalled = true
}

type fakeSlot struct {
	manager.Slot

	authorityID string
	notAfter    time.Time
	publicKey   crypto.PublicKey
	status      journal.Status
}

func (s *fakeSlot) AuthorityID() string {
	return s.authorityID
}

func (s *fakeSlot) NotAfter() time.Time {
	return s.notAfter
}

func (s *fakeSlot) PublicKey() crypto.PublicKey {
	return s.publicKey
}

func (s *fakeSlot) Status() journal.Status {
	return s.status
}

func createSlot(status journal.Status, authorityID string, publicKey crypto.PublicKey, notAfter time.Time) *fakeSlot {
	return &fakeSlot{
		authorityID: authorityID,
		notAfter:    notAfter,
		publicKey:   publicKey,
		status:      status,
	}
}
