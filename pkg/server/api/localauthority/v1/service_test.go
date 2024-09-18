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
	"github.com/spiffe/spire/test/grpctest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/spiffe/spire/test/testkey"
	testutil "github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

var (
	ctx               = context.Background()
	serverTrustDomain = spiffeid.RequireTrustDomainFromString("example.org")
	keyA              = testkey.MustEC256()
	keyB              = testkey.MustEC256()
	keyC              = testkey.MustEC256()
	keyABytes, _      = x509util.GetSubjectKeyID(keyA.Public())
	keyBBytes, _      = x509util.GetSubjectKeyID(keyB.Public())
	authorityIDKeyA   = x509util.SubjectKeyIDToString(keyABytes)
	authorityIDKeyB   = x509util.SubjectKeyIDToString(keyBBytes)
	notAfterCurrent   = time.Now().Add(time.Minute)
	notAfterNext      = notAfterCurrent.Add(time.Minute)
)

func TestGetJWTAuthorityState(t *testing.T) {
	for _, tt := range []struct {
		name        string
		currentSlot *fakeSlot
		nextSlot    *fakeSlot
		expectLogs  []spiretest.LogEntry
		expectCode  codes.Code
		expectMsg   string
		expectResp  *localauthorityv1.GetJWTAuthorityStateResponse
	}{
		{
			name:        "current is set",
			currentSlot: createSlot(journal.Status_ACTIVE, authorityIDKeyA, keyA.Public(), notAfterCurrent),
			nextSlot:    &fakeSlot{},
			expectResp: &localauthorityv1.GetJWTAuthorityStateResponse{
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
			expectResp: &localauthorityv1.GetJWTAuthorityStateResponse{
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
			name:        "next contains a prepared authority",
			currentSlot: createSlot(journal.Status_ACTIVE, authorityIDKeyA, keyA.Public(), notAfterCurrent),
			nextSlot:    createSlot(journal.Status_PREPARED, authorityIDKeyB, keyB.Public(), notAfterNext),
			expectResp: &localauthorityv1.GetJWTAuthorityStateResponse{
				Active: &localauthorityv1.AuthorityState{
					AuthorityId: authorityIDKeyA,
					ExpiresAt:   notAfterCurrent.Unix(),
				},
				Prepared: &localauthorityv1.AuthorityState{
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
			name:        "next contains an unknown authority",
			currentSlot: createSlot(journal.Status_ACTIVE, authorityIDKeyA, keyA.Public(), notAfterCurrent),
			nextSlot:    createSlot(journal.Status_UNKNOWN, authorityIDKeyB, keyB.Public(), notAfterNext),
			expectResp: &localauthorityv1.GetJWTAuthorityStateResponse{
				Active: &localauthorityv1.AuthorityState{
					AuthorityId: authorityIDKeyA,
					ExpiresAt:   notAfterCurrent.Unix(),
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Slot has an unknown status",
					Data: logrus.Fields{
						telemetry.LocalAuthorityID: authorityIDKeyB,
					},
				},
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
			name:        "current slot has no authority ID",
			currentSlot: createSlot(journal.Status_ACTIVE, "", nil, time.Time{}),
			nextSlot:    &fakeSlot{},
			expectCode:  codes.Internal,
			expectMsg:   "current slot does not contain authority ID",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Current slot does not contain authority ID",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "current slot does not contain authority ID",
						telemetry.Type:          "audit",
					},
				},
			},
		},
	} {
		test := setupServiceTest(t)
		defer test.Cleanup()

		test.ca.currentJWTKeySlot = tt.currentSlot
		test.ca.nextJWTKeySlot = tt.nextSlot

		resp, err := test.client.GetJWTAuthorityState(ctx, &localauthorityv1.GetJWTAuthorityStateRequest{})

		spiretest.AssertGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
		spiretest.AssertProtoEqual(t, tt.expectResp, resp)
		spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
	}
}

func TestPrepareJWTAuthority(t *testing.T) {
	for _, tt := range []struct {
		name        string
		currentSlot *fakeSlot
		prepareErr  error
		nextSlot    *fakeSlot
		expectLogs  []spiretest.LogEntry
		expectCode  codes.Code
		expectMsg   string
		expectResp  *localauthorityv1.PrepareJWTAuthorityResponse
	}{
		{
			name:        "using next to prepare",
			currentSlot: createSlot(journal.Status_ACTIVE, authorityIDKeyA, keyA.Public(), notAfterCurrent),
			nextSlot:    createSlot(journal.Status_OLD, authorityIDKeyB, keyB.Public(), notAfterNext),
			expectResp: &localauthorityv1.PrepareJWTAuthorityResponse{
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
			expectMsg:   "failed to prepare JWT authority: oh no",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to prepare JWT authority",
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
						telemetry.StatusMessage: "failed to prepare JWT authority: oh no",
						telemetry.Type:          "audit",
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t)
			defer test.Cleanup()

			test.ca.currentJWTKeySlot = tt.currentSlot
			test.ca.nextJWTKeySlot = tt.nextSlot
			test.ca.prepareJWTKeyErr = tt.prepareErr

			resp, err := test.client.PrepareJWTAuthority(ctx, &localauthorityv1.PrepareJWTAuthorityRequest{})

			spiretest.AssertGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			spiretest.AssertProtoEqual(t, tt.expectResp, resp)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
		})
	}
}

func TestActivateJWTAuthority(t *testing.T) {
	for _, tt := range []struct {
		name        string
		currentSlot *fakeSlot
		nextSlot    *fakeSlot

		rotateCalled  bool
		keyToActivate string
		expectLogs    []spiretest.LogEntry
		expectCode    codes.Code
		expectMsg     string
		expectResp    *localauthorityv1.ActivateJWTAuthorityResponse
	}{
		{
			name:          "activate successfully",
			currentSlot:   createSlot(journal.Status_ACTIVE, authorityIDKeyA, keyA.Public(), notAfterCurrent),
			nextSlot:      createSlot(journal.Status_PREPARED, authorityIDKeyB, keyB.Public(), notAfterNext),
			keyToActivate: authorityIDKeyB,
			rotateCalled:  true,
			expectResp: &localauthorityv1.ActivateJWTAuthorityResponse{
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
			expectMsg:     "only Prepared authorities can be activated: unsupported local authority status: OLD",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Only Prepared authorities can be activated",
					Data: logrus.Fields{
						telemetry.LocalAuthorityID: authorityIDKeyB,
						logrus.ErrorKey:            "unsupported local authority status: OLD",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "Internal",
						telemetry.StatusMessage:    "only Prepared authorities can be activated: unsupported local authority status: OLD",
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

			test.ca.currentJWTKeySlot = tt.currentSlot
			test.ca.nextJWTKeySlot = tt.nextSlot

			resp, err := test.client.ActivateJWTAuthority(ctx, &localauthorityv1.ActivateJWTAuthorityRequest{
				AuthorityId: tt.keyToActivate,
			})

			require.Equal(t, tt.rotateCalled, test.ca.rotateJWTKeyCalled)
			spiretest.AssertGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			spiretest.AssertProtoEqual(t, tt.expectResp, resp)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
		})
	}
}

func TestTaintJWTAuthority(t *testing.T) {
	clk := clock.New()

	currentKey := keyA
	currentPublicKeyRaw, err := x509.MarshalPKIXPublicKey(currentKey.Public())
	require.NoError(t, err)
	currentAuthorityID := "key1"
	currentKeyNotAfter := clk.Now().Add(time.Minute)

	nextKey := keyB
	nextPublicKeyRaw, err := x509.MarshalPKIXPublicKey(nextKey.Public())
	require.NoError(t, err)
	nextAuthorityID := "key2"
	nextKeyNotAfter := clk.Now().Add(2 * time.Minute)

	for _, tt := range []struct {
		name        string
		currentSlot *fakeSlot
		nextSlot    *fakeSlot
		keyToTaint  string

		expectLogs       []spiretest.LogEntry
		expectCode       codes.Code
		expectMsg        string
		expectResp       *localauthorityv1.TaintJWTAuthorityResponse
		nextKeyIsTainted bool
	}{
		{
			name:        "taint old authority",
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), currentKeyNotAfter),
			nextSlot:    createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), nextKeyNotAfter),
			keyToTaint:  nextAuthorityID,
			expectResp: &localauthorityv1.TaintJWTAuthorityResponse{
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
					Message: "JWT authority tainted successfully",
					Data: logrus.Fields{
						telemetry.LocalAuthorityID: nextAuthorityID,
					},
				},
			},
		},
		{
			name:        "no authority ID provided",
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), currentKeyNotAfter),
			nextSlot:    createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), nextKeyNotAfter),
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
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), currentKeyNotAfter),
			nextSlot:    createSlot(journal.Status_PREPARED, nextAuthorityID, nextKey.Public(), nextKeyNotAfter),
			keyToTaint:  nextAuthorityID,
			expectCode:  codes.InvalidArgument,
			expectMsg:   "only Old local authorities can be tainted",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: only Old local authorities can be tainted",
					Data: logrus.Fields{
						logrus.ErrorKey:            "unsupported local authority status: PREPARED",
						telemetry.LocalAuthorityID: nextAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "InvalidArgument",
						telemetry.StatusMessage:    "only Old local authorities can be tainted: unsupported local authority status: PREPARED",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: nextAuthorityID,
					},
				},
			},
		},
		{
			name:        "unable to taint current key",
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), currentKeyNotAfter),
			nextSlot:    createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), nextKeyNotAfter),
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
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), currentKeyNotAfter),
			nextSlot:    createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), nextKeyNotAfter),
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
			name:             "failed to taint already tainted key",
			currentSlot:      createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), currentKeyNotAfter),
			nextSlot:         createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), nextKeyNotAfter),
			keyToTaint:       nextAuthorityID,
			nextKeyIsTainted: true,
			expectCode:       codes.Internal,
			expectMsg:        "failed to taint JWT authority: key is already tainted",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to taint JWT authority",
					Data: logrus.Fields{
						logrus.ErrorKey:            "rpc error: code = InvalidArgument desc = key is already tainted",
						telemetry.LocalAuthorityID: nextAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "Internal",
						telemetry.StatusMessage:    "failed to taint JWT authority: key is already tainted",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: nextAuthorityID,
					},
				},
			},
		},
	} {
		test := setupServiceTest(t)
		defer test.Cleanup()

		test.ca.currentJWTKeySlot = tt.currentSlot
		test.ca.nextJWTKeySlot = tt.nextSlot
		_, err := test.ds.CreateBundle(ctx, &common.Bundle{
			TrustDomainId: serverTrustDomain.IDString(),
			JwtSigningKeys: []*common.PublicKey{
				{
					PkixBytes: currentPublicKeyRaw,
					Kid:       currentAuthorityID,
					NotAfter:  currentKeyNotAfter.Unix(),
				},
				{
					PkixBytes:  nextPublicKeyRaw,
					Kid:        nextAuthorityID,
					NotAfter:   nextKeyNotAfter.Unix(),
					TaintedKey: tt.nextKeyIsTainted,
				},
			},
		})
		require.NoError(t, err)

		resp, err := test.client.TaintJWTAuthority(ctx, &localauthorityv1.TaintJWTAuthorityRequest{
			AuthorityId: tt.keyToTaint,
		})

		spiretest.AssertGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsg)
		spiretest.AssertProtoEqual(t, tt.expectResp, resp)
		spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
	}
}

func TestRevokeJWTAuthority(t *testing.T) {
	clk := clock.New()

	currentKey := keyA
	currentPublicKeyRaw, err := x509.MarshalPKIXPublicKey(currentKey.Public())
	require.NoError(t, err)
	currentAuthorityID := "key1"
	currentKeyNotAfter := clk.Now().Add(time.Minute)

	nextKey := keyB
	nextPublicKeyRaw, err := x509.MarshalPKIXPublicKey(nextKey.Public())
	require.NoError(t, err)
	nextAuthorityID := "key2"
	nextKeyNotAfter := clk.Now().Add(time.Minute)

	oldKey := keyC
	oldPublicKeyRaw, err := x509.MarshalPKIXPublicKey(oldKey.Public())
	require.NoError(t, err)
	oldAuthorityID := "key3"
	oldKeyNotAfter := clk.Now()

	for _, tt := range []struct {
		name          string
		currentSlot   *fakeSlot
		nextSlot      *fakeSlot
		keyToRevoke   string
		noTaintedKeys bool

		expectLogs []spiretest.LogEntry
		expectCode codes.Code
		expectMsg  string
		expectResp *localauthorityv1.RevokeJWTAuthorityResponse
	}{
		{
			name:        "revoke authority from parameter",
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), currentKeyNotAfter),
			nextSlot:    createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), nextKeyNotAfter),
			keyToRevoke: oldAuthorityID,
			expectResp: &localauthorityv1.RevokeJWTAuthorityResponse{
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
					Message: "JWT authority revoked successfully",
					Data: logrus.Fields{
						telemetry.LocalAuthorityID: oldAuthorityID,
					},
				},
			},
		},
		{
			name:        "no authority ID provided",
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), currentKeyNotAfter),
			nextSlot:    createSlot(journal.Status_PREPARED, nextAuthorityID, nextKey.Public(), nextKeyNotAfter),
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
			name:        "not allow to revoke a prepared key",
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), currentKeyNotAfter),
			nextSlot:    createSlot(journal.Status_PREPARED, nextAuthorityID, nextKey.Public(), nextKeyNotAfter),
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
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), currentKeyNotAfter),
			nextSlot:    createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), nextKeyNotAfter),
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
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), currentKeyNotAfter),
			nextSlot:    createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), nextKeyNotAfter),
			keyToRevoke: authorityIDKeyA,
			expectCode:  codes.InvalidArgument,
			expectMsg:   "invalid authority ID: no JWT authority found with provided authority ID",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid authority ID",
					Data: logrus.Fields{
						logrus.ErrorKey:            "no JWT authority found with provided authority ID",
						telemetry.LocalAuthorityID: authorityIDKeyA,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "InvalidArgument",
						telemetry.StatusMessage:    "invalid authority ID: no JWT authority found with provided authority ID",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: authorityIDKeyA,
					},
				},
			},
		},
		{
			name:          "failed to revoke untainted key",
			currentSlot:   createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), currentKeyNotAfter),
			nextSlot:      createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), currentKeyNotAfter),
			keyToRevoke:   nextAuthorityID,
			noTaintedKeys: true,
			expectCode:    codes.Internal,
			expectMsg:     "failed to revoke JWT authority: it is not possible to revoke an untainted key",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to revoke JWT authority",
					Data: logrus.Fields{
						logrus.ErrorKey:            "rpc error: code = InvalidArgument desc = it is not possible to revoke an untainted key",
						telemetry.LocalAuthorityID: nextAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "Internal",
						telemetry.StatusMessage:    "failed to revoke JWT authority: it is not possible to revoke an untainted key",
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

			test.ca.currentJWTKeySlot = tt.currentSlot
			test.ca.nextJWTKeySlot = tt.nextSlot

			_, err := test.ds.CreateBundle(ctx, &common.Bundle{
				TrustDomainId: serverTrustDomain.IDString(),
				JwtSigningKeys: []*common.PublicKey{
					{
						PkixBytes: currentPublicKeyRaw,
						Kid:       currentAuthorityID,
						NotAfter:  currentKeyNotAfter.Unix(),
					},
					{
						PkixBytes:  nextPublicKeyRaw,
						Kid:        nextAuthorityID,
						NotAfter:   nextKeyNotAfter.Unix(),
						TaintedKey: !tt.noTaintedKeys,
					},
					{
						PkixBytes:  oldPublicKeyRaw,
						Kid:        oldAuthorityID,
						NotAfter:   oldKeyNotAfter.Unix(),
						TaintedKey: !tt.noTaintedKeys,
					},
				},
			})
			require.NoError(t, err)

			resp, err := test.client.RevokeJWTAuthority(ctx, &localauthorityv1.RevokeJWTAuthorityRequest{
				AuthorityId: tt.keyToRevoke,
			})

			spiretest.AssertGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsg)
			spiretest.AssertProtoEqual(t, tt.expectResp, resp)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
		})
	}
}

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
			expectMsg:   "current slot does not contain authority ID",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Current slot does not contain authority ID",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "current slot does not contain authority ID",
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
			expectMsg:     "only Prepared authorities can be activated: unsupported local authority status: OLD",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Only Prepared authorities can be activated",
					Data: logrus.Fields{
						logrus.ErrorKey:            "unsupported local authority status: OLD",
						telemetry.LocalAuthorityID: authorityIDKeyB,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "Internal",
						telemetry.StatusMessage:    "only Prepared authorities can be activated: unsupported local authority status: OLD",
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
	nextKeySKI, err := x509util.GetSubjectKeyID(nextKey.Public())
	require.NoError(t, err)
	nextAuthorityID := x509util.SubjectKeyIDToString(nextKeySKI)

	oldCA, _, err := testutil.SelfSign(template)
	require.NoError(t, err)

	defaultRootCAs := []*common.Certificate{
		{
			DerBytes: currentCA.Raw,
		},
		{
			DerBytes: nextCA.Raw,
		},
		{
			DerBytes: oldCA.Raw,
		},
	}

	for _, tt := range []struct {
		name                string
		currentSlot         *fakeSlot
		nextSlot            *fakeSlot
		keyToTaint          string
		customRootCAs       []*common.Certificate
		isUpstreamAuthority bool
		notifyTaintedErr    error

		expectLogs []spiretest.LogEntry
		expectCode codes.Code
		expectMsg  string
		expectResp *localauthorityv1.TaintX509AuthorityResponse
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
			expectMsg:   "only Old local authorities can be tainted: unsupported local authority status: PREPARED",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: only Old local authorities can be tainted",
					Data: logrus.Fields{
						logrus.ErrorKey:            "unsupported local authority status: PREPARED",
						telemetry.LocalAuthorityID: nextAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "InvalidArgument",
						telemetry.StatusMessage:    "only Old local authorities can be tainted: unsupported local authority status: PREPARED",
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
			customRootCAs: []*common.Certificate{
				{
					DerBytes: currentCA.Raw,
				},
				{
					DerBytes:   nextCA.Raw,
					TaintedKey: true,
				},
				{
					DerBytes: oldCA.Raw,
				},
			},
			expectCode: codes.Internal,
			expectMsg:  "failed to taint X.509 authority: root CA is already tainted",
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
		{
			name:                "fail on upstream authority",
			currentSlot:         createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), notAfterCurrent),
			nextSlot:            createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), notAfterNext),
			keyToTaint:          nextAuthorityID,
			isUpstreamAuthority: true,
			expectCode:          codes.FailedPrecondition,
			expectMsg:           "local authority can't be tainted if there is an upstream authority",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Local authority can't be tainted if there is an upstream authority",
					Data: logrus.Fields{
						telemetry.LocalAuthorityID: nextAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "FailedPrecondition",
						telemetry.StatusMessage:    "local authority can't be tainted if there is an upstream authority",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: nextAuthorityID,
					},
				},
			},
		},
		{
			name:             "fail to notify tainted authority",
			currentSlot:      createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), notAfterCurrent),
			nextSlot:         createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), notAfterNext),
			keyToTaint:       nextAuthorityID,
			notifyTaintedErr: errors.New("oh no"),
			expectCode:       codes.Internal,
			expectMsg:        "failed to notify tainted authority: oh no",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to notify tainted authority",
					Data: logrus.Fields{
						telemetry.LocalAuthorityID: nextAuthorityID,
						logrus.ErrorKey:            "oh no",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "Internal",
						telemetry.StatusMessage:    "failed to notify tainted authority: oh no",
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
			test.ca.isUpstreamAuthority = tt.isUpstreamAuthority
			test.ca.notifyTaintedExpectErr = tt.notifyTaintedErr

			rootCAs := defaultRootCAs
			if tt.customRootCAs != nil {
				rootCAs = tt.customRootCAs
			}

			_, err := test.ds.CreateBundle(ctx, &common.Bundle{
				TrustDomainId: serverTrustDomain.IDString(),
				RootCas:       rootCAs,
			})
			require.NoError(t, err)

			resp, err := test.client.TaintX509Authority(ctx, &localauthorityv1.TaintX509AuthorityRequest{
				AuthorityId: tt.keyToTaint,
			})

			spiretest.AssertGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsg)
			spiretest.AssertProtoEqual(t, tt.expectResp, resp)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
			// Validate notification is received on success test cases
			if tt.expectMsg == "" {
				assert.Equal(t, tt.keyToTaint, test.ca.notifyTaintedAuthorityID)
			}
		})
	}
}

func TestTaintX509UpstreamAuthority(t *testing.T) {
	getUpstreamCertAndSubjectID := func(ca *testca.CA) (*x509.Certificate, string) {
		// Self signed CA will return itself
		cert := ca.X509Authorities()[0]
		return cert, x509util.SubjectKeyIDToString(cert.SubjectKeyId)
	}

	// Create active upstream authority
	activeUpstreamAuthority := testca.New(t, serverTrustDomain)
	activeUpstreamAuthorityCert, activeUpstreamAuthorityID := getUpstreamCertAndSubjectID(activeUpstreamAuthority)

	// Create newUpstreamAuthority childs
	currentIntermediateCA := activeUpstreamAuthority.ChildCA(testca.WithID(serverTrustDomain.ID()))
	nextIntermediateCA := activeUpstreamAuthority.ChildCA(testca.WithID(serverTrustDomain.ID()))

	// Create old upstream authority
	deactivatedUpstreamAuthority := testca.New(t, serverTrustDomain)
	deactivatedUpstreamAuthorityCert, deactivatedUpstreamAuthorityID := getUpstreamCertAndSubjectID(deactivatedUpstreamAuthority)

	// Create intermediate using old upstream authority
	oldIntermediateCA := deactivatedUpstreamAuthority.ChildCA(testca.WithID(serverTrustDomain.ID()))

	defaultRootCAs := []*common.Certificate{
		{
			DerBytes: activeUpstreamAuthorityCert.Raw,
		},
		{
			DerBytes: deactivatedUpstreamAuthorityCert.Raw,
		},
	}

	for _, tt := range []struct {
		name                string
		currentSlot         *fakeSlot
		nextSlot            *fakeSlot
		subjectKeyIDToTaint string
		customRootCAs       []*common.Certificate
		isLocalAuthority    bool

		expectLogs []spiretest.LogEntry
		expectCode codes.Code
		expectMsg  string
		expectResp *localauthorityv1.TaintX509UpstreamAuthorityResponse
	}{
		{
			name:                "taint old upstream authority",
			currentSlot:         createSlotWithUpstream(journal.Status_ACTIVE, currentIntermediateCA, notAfterCurrent),
			nextSlot:            createSlotWithUpstream(journal.Status_OLD, oldIntermediateCA, notAfterNext),
			subjectKeyIDToTaint: deactivatedUpstreamAuthorityID,
			expectResp:          &localauthorityv1.TaintX509UpstreamAuthorityResponse{},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:       "success",
						telemetry.Type:         "audit",
						telemetry.SubjectKeyID: deactivatedUpstreamAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "X.509 upstream authority tainted successfully",
					Data: logrus.Fields{
						telemetry.SubjectKeyID: deactivatedUpstreamAuthorityID,
					},
				},
			},
		},
		{
			name:                "unable to taint with upstream disabled",
			currentSlot:         createSlotWithUpstream(journal.Status_ACTIVE, currentIntermediateCA, notAfterCurrent),
			nextSlot:            createSlotWithUpstream(journal.Status_OLD, oldIntermediateCA, notAfterNext),
			subjectKeyIDToTaint: deactivatedUpstreamAuthorityID,
			expectCode:          codes.FailedPrecondition,
			expectMsg:           "upstream authority is not configured",
			isLocalAuthority:    true,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Upstream authority is not configured",
					Data: logrus.Fields{
						telemetry.SubjectKeyID: deactivatedUpstreamAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "FailedPrecondition",
						telemetry.StatusMessage: "upstream authority is not configured",
						telemetry.Type:          "audit",
						telemetry.SubjectKeyID:  deactivatedUpstreamAuthorityID,
					},
				},
			},
		},
		{
			name:        "no subjectID provided",
			currentSlot: createSlotWithUpstream(journal.Status_ACTIVE, currentIntermediateCA, notAfterCurrent),
			nextSlot:    createSlotWithUpstream(journal.Status_OLD, oldIntermediateCA, notAfterNext),
			expectCode:  codes.InvalidArgument,
			expectMsg:   "provided subject key id is not valid: no subject key ID provided",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: provided subject key id is not valid",
					Data: logrus.Fields{
						logrus.ErrorKey: "no subject key ID provided",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "provided subject key id is not valid: no subject key ID provided",
						telemetry.Type:          "audit",
					},
				},
			},
		},
		{
			name:                "unable to use active upstream authority",
			currentSlot:         createSlotWithUpstream(journal.Status_ACTIVE, currentIntermediateCA, notAfterCurrent),
			nextSlot:            createSlotWithUpstream(journal.Status_OLD, nextIntermediateCA, notAfterNext),
			subjectKeyIDToTaint: activeUpstreamAuthorityID,
			expectCode:          codes.InvalidArgument,
			expectMsg:           "provided subject key id is not valid: unable to use upstream authority singing current authority",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: provided subject key id is not valid",
					Data: logrus.Fields{
						logrus.ErrorKey:        "unable to use upstream authority singing current authority",
						telemetry.SubjectKeyID: activeUpstreamAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "provided subject key id is not valid: unable to use upstream authority singing current authority",
						telemetry.Type:          "audit",
						telemetry.SubjectKeyID:  activeUpstreamAuthorityID,
					},
				},
			},
		},
		{
			name:                "unknown subjectKeyID",
			currentSlot:         createSlotWithUpstream(journal.Status_ACTIVE, currentIntermediateCA, notAfterCurrent),
			nextSlot:            createSlotWithUpstream(journal.Status_OLD, nextIntermediateCA, notAfterNext),
			subjectKeyIDToTaint: "invalidID",
			expectCode:          codes.InvalidArgument,
			expectMsg:           "provided subject key id is not valid: upstream authority didn't sign the old local authority",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: provided subject key id is not valid",
					Data: logrus.Fields{
						logrus.ErrorKey:        "upstream authority didn't sign the old local authority",
						telemetry.SubjectKeyID: "invalidID",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "provided subject key id is not valid: upstream authority didn't sign the old local authority",
						telemetry.Type:          "audit",
						telemetry.SubjectKeyID:  "invalidID",
					},
				},
			},
		},
		{
			name:                "prepared authority signed by upstream authority",
			currentSlot:         createSlotWithUpstream(journal.Status_ACTIVE, currentIntermediateCA, notAfterCurrent),
			nextSlot:            createSlotWithUpstream(journal.Status_PREPARED, oldIntermediateCA, notAfterNext),
			subjectKeyIDToTaint: deactivatedUpstreamAuthorityID,
			expectCode:          codes.InvalidArgument,
			expectMsg:           "provided subject key id is not valid: only upstream authorities signing an old authority can be used",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: provided subject key id is not valid",
					Data: logrus.Fields{
						logrus.ErrorKey:        "only upstream authorities signing an old authority can be used",
						telemetry.SubjectKeyID: deactivatedUpstreamAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "provided subject key id is not valid: only upstream authorities signing an old authority can be used",
						telemetry.Type:          "audit",
						telemetry.SubjectKeyID:  deactivatedUpstreamAuthorityID,
					},
				},
			},
		},
		{
			name:                "ds failed to taint",
			currentSlot:         createSlotWithUpstream(journal.Status_ACTIVE, currentIntermediateCA, notAfterCurrent),
			nextSlot:            createSlotWithUpstream(journal.Status_OLD, oldIntermediateCA, notAfterNext),
			subjectKeyIDToTaint: deactivatedUpstreamAuthorityID,
			expectCode:          codes.Internal,
			expectMsg:           "failed to taint upstream authority: no ca found with provided subject key ID",
			customRootCAs: []*common.Certificate{
				{
					DerBytes: activeUpstreamAuthorityCert.Raw,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to taint upstream authority",
					Data: logrus.Fields{
						logrus.ErrorKey:        "rpc error: code = NotFound desc = no ca found with provided subject key ID",
						telemetry.SubjectKeyID: deactivatedUpstreamAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to taint upstream authority: no ca found with provided subject key ID",
						telemetry.Type:          "audit",
						telemetry.SubjectKeyID:  deactivatedUpstreamAuthorityID,
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
			test.ca.isUpstreamAuthority = !tt.isLocalAuthority

			rootCAs := defaultRootCAs
			if tt.customRootCAs != nil {
				rootCAs = tt.customRootCAs
			}

			_, err := test.ds.CreateBundle(ctx, &common.Bundle{
				TrustDomainId: serverTrustDomain.IDString(),
				RootCas:       rootCAs,
			})
			require.NoError(t, err)

			resp, err := test.client.TaintX509UpstreamAuthority(ctx, &localauthorityv1.TaintX509UpstreamAuthorityRequest{
				SubjectKeyId: tt.subjectKeyIDToTaint,
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

	_, noStoredKey, err := testutil.SelfSign(template)
	require.NoError(t, err)
	noStoredKeySKI, err := x509util.GetSubjectKeyID(noStoredKey.Public())
	require.NoError(t, err)
	noStoredAuthorityID := x509util.SubjectKeyIDToString(noStoredKeySKI)

	for _, tt := range []struct {
		name                string
		currentSlot         *fakeSlot
		nextSlot            *fakeSlot
		keyToRevoke         string
		noTaintedKeys       bool
		isUpstreamAuthority bool

		expectLogs []spiretest.LogEntry
		expectCode codes.Code
		expectMsg  string
		expectResp *localauthorityv1.RevokeX509AuthorityResponse
	}{
		{
			name:        "revoke authority from parameter",
			currentSlot: createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), notAfterCurrent),
			nextSlot:    createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), notAfterNext),
			keyToRevoke: nextAuthorityID,
			expectResp: &localauthorityv1.RevokeX509AuthorityResponse{
				RevokedAuthority: &localauthorityv1.AuthorityState{
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
					Message: "X.509 authority revoked successfully",
					Data: logrus.Fields{
						telemetry.LocalAuthorityID: nextAuthorityID,
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
			expectMsg:   "invalid authority ID: only Old local authority can be revoked",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid authority ID",
					Data: logrus.Fields{
						logrus.ErrorKey:            "only Old local authority can be revoked",
						telemetry.LocalAuthorityID: nextAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "InvalidArgument",
						telemetry.StatusMessage:    "invalid authority ID: only Old local authority can be revoked",
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
			nextSlot:    createSlot(journal.Status_OLD, noStoredAuthorityID, noStoredKey.Public(), notAfterNext),
			keyToRevoke: noStoredAuthorityID,
			expectCode:  codes.Internal,
			expectMsg:   "failed to revoke X.509 authority: no root CA found with provided subject key ID",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to revoke X.509 authority",
					Data: logrus.Fields{
						logrus.ErrorKey:            "rpc error: code = NotFound desc = no root CA found with provided subject key ID",
						telemetry.LocalAuthorityID: noStoredAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "Internal",
						telemetry.StatusMessage:    "failed to revoke X.509 authority: no root CA found with provided subject key ID",
						telemetry.Type:             "audit",
						telemetry.LocalAuthorityID: noStoredAuthorityID,
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
		{
			name:                "unable to revoke upstream authority",
			currentSlot:         createSlot(journal.Status_ACTIVE, currentAuthorityID, currentKey.Public(), notAfterCurrent),
			nextSlot:            createSlot(journal.Status_OLD, nextAuthorityID, nextKey.Public(), notAfterNext),
			keyToRevoke:         nextAuthorityID,
			isUpstreamAuthority: true,
			expectCode:          codes.FailedPrecondition,
			expectMsg:           "local authority can't be revoked if there is an upstream authority",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Local authority can't be revoked if there is an upstream authority",
					Data: logrus.Fields{
						telemetry.LocalAuthorityID: nextAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.StatusCode:       "FailedPrecondition",
						telemetry.StatusMessage:    "local authority can't be revoked if there is an upstream authority",
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
			test.ca.isUpstreamAuthority = tt.isUpstreamAuthority

			_, err := test.ds.CreateBundle(ctx, &common.Bundle{
				TrustDomainId: serverTrustDomain.IDString(),
				RootCas: []*common.Certificate{
					{
						DerBytes: currentCA.Raw,
					},
					{
						DerBytes:   nextCA.Raw,
						TaintedKey: !tt.noTaintedKeys,
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

func TestRevokeX509UpstreamAuthority(t *testing.T) {
	getUpstreamCertAndSubjectID := func(ca *testca.CA) (*x509.Certificate, string) {
		// Self signed CA will return itself
		cert := ca.X509Authorities()[0]
		return cert, x509util.SubjectKeyIDToString(cert.SubjectKeyId)
	}

	// Create active upstream authority
	activeUpstreamAuthority := testca.New(t, serverTrustDomain)
	activeUpstreamAuthorityCert, activeUpstreamAuthorityID := getUpstreamCertAndSubjectID(activeUpstreamAuthority)

	// Create newUpstreamAuthority childs
	currentIntermediateCA := activeUpstreamAuthority.ChildCA(testca.WithID(serverTrustDomain.ID()))
	nextIntermediateCA := activeUpstreamAuthority.ChildCA(testca.WithID(serverTrustDomain.ID()))

	// Create old upstream authority
	deactivatedUpstreamAuthority := testca.New(t, serverTrustDomain)
	deactivatedUpstreamAuthorityCert, deactivatedUpstreamAuthorityID := getUpstreamCertAndSubjectID(deactivatedUpstreamAuthority)

	// Create intermediate using old upstream authority
	oldIntermediateCA := deactivatedUpstreamAuthority.ChildCA(testca.WithID(serverTrustDomain.ID()))

	for _, tt := range []struct {
		name                 string
		currentSlot          *fakeSlot
		nextSlot             *fakeSlot
		subjectKeyIDToRevoke string
		noTaintedKeys        bool
		isLocalAuthority     bool

		expectLogs []spiretest.LogEntry
		expectCode codes.Code
		expectMsg  string
		expectResp *localauthorityv1.RevokeX509UpstreamAuthorityResponse
	}{
		{
			name:                 "revoke authority",
			currentSlot:          createSlotWithUpstream(journal.Status_ACTIVE, currentIntermediateCA, notAfterCurrent),
			nextSlot:             createSlotWithUpstream(journal.Status_OLD, oldIntermediateCA, notAfterNext),
			subjectKeyIDToRevoke: deactivatedUpstreamAuthorityID,
			expectResp:           &localauthorityv1.RevokeX509UpstreamAuthorityResponse{},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:       "success",
						telemetry.Type:         "audit",
						telemetry.SubjectKeyID: deactivatedUpstreamAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "X.509 upstream authority successfully revoked",
					Data: logrus.Fields{
						telemetry.SubjectKeyID: deactivatedUpstreamAuthorityID,
					},
				},
			},
		},
		{
			name:                 "unable to revoke with upstream disabled",
			currentSlot:          createSlotWithUpstream(journal.Status_ACTIVE, currentIntermediateCA, notAfterCurrent),
			nextSlot:             createSlotWithUpstream(journal.Status_OLD, oldIntermediateCA, notAfterNext),
			subjectKeyIDToRevoke: deactivatedUpstreamAuthorityID,
			expectCode:           codes.FailedPrecondition,
			expectMsg:            "upstream authority is not configured",
			isLocalAuthority:     true,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Upstream authority is not configured",
					Data: logrus.Fields{
						telemetry.SubjectKeyID: deactivatedUpstreamAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "FailedPrecondition",
						telemetry.StatusMessage: "upstream authority is not configured",
						telemetry.Type:          "audit",
						telemetry.SubjectKeyID:  deactivatedUpstreamAuthorityID,
					},
				},
			},
		},
		{
			name:        "no subjectID provided",
			currentSlot: createSlotWithUpstream(journal.Status_ACTIVE, currentIntermediateCA, notAfterCurrent),
			nextSlot:    createSlotWithUpstream(journal.Status_OLD, oldIntermediateCA, notAfterNext),
			expectCode:  codes.InvalidArgument,
			expectMsg:   "invalid subject key ID: no subject key ID provided",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid subject key ID",
					Data: logrus.Fields{
						logrus.ErrorKey: "no subject key ID provided",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "invalid subject key ID: no subject key ID provided",
						telemetry.Type:          "audit",
					},
				},
			},
		},
		{
			name:                 "unable to use active upstream authority",
			currentSlot:          createSlotWithUpstream(journal.Status_ACTIVE, currentIntermediateCA, notAfterCurrent),
			nextSlot:             createSlotWithUpstream(journal.Status_OLD, nextIntermediateCA, notAfterNext),
			subjectKeyIDToRevoke: activeUpstreamAuthorityID,
			expectCode:           codes.InvalidArgument,
			expectMsg:            "invalid subject key ID: unable to use upstream authority singing current authority",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid subject key ID",
					Data: logrus.Fields{
						logrus.ErrorKey:        "unable to use upstream authority singing current authority",
						telemetry.SubjectKeyID: activeUpstreamAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "invalid subject key ID: unable to use upstream authority singing current authority",
						telemetry.Type:          "audit",
						telemetry.SubjectKeyID:  activeUpstreamAuthorityID,
					},
				},
			},
		},
		{
			name:                 "unknown subjectKeyID",
			currentSlot:          createSlotWithUpstream(journal.Status_ACTIVE, currentIntermediateCA, notAfterCurrent),
			nextSlot:             createSlotWithUpstream(journal.Status_OLD, nextIntermediateCA, notAfterNext),
			subjectKeyIDToRevoke: "invalidID",
			expectCode:           codes.InvalidArgument,
			expectMsg:            "invalid subject key ID: upstream authority didn't sign the old local authority",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid subject key ID",
					Data: logrus.Fields{
						logrus.ErrorKey:        "upstream authority didn't sign the old local authority",
						telemetry.SubjectKeyID: "invalidID",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "invalid subject key ID: upstream authority didn't sign the old local authority",
						telemetry.Type:          "audit",
						telemetry.SubjectKeyID:  "invalidID",
					},
				},
			},
		},
		{
			name:                 "prepared authority signed by upstream authority",
			currentSlot:          createSlotWithUpstream(journal.Status_ACTIVE, currentIntermediateCA, notAfterCurrent),
			nextSlot:             createSlotWithUpstream(journal.Status_PREPARED, oldIntermediateCA, notAfterNext),
			subjectKeyIDToRevoke: deactivatedUpstreamAuthorityID,
			expectCode:           codes.InvalidArgument,
			expectMsg:            "invalid subject key ID: only upstream authorities signing an old authority can be used",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid subject key ID",
					Data: logrus.Fields{
						logrus.ErrorKey:        "only upstream authorities signing an old authority can be used",
						telemetry.SubjectKeyID: deactivatedUpstreamAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "invalid subject key ID: only upstream authorities signing an old authority can be used",
						telemetry.Type:          "audit",
						telemetry.SubjectKeyID:  deactivatedUpstreamAuthorityID,
					},
				},
			},
		},
		{
			name:                 "ds failed revoke untainted keys",
			currentSlot:          createSlotWithUpstream(journal.Status_ACTIVE, currentIntermediateCA, notAfterCurrent),
			nextSlot:             createSlotWithUpstream(journal.Status_OLD, oldIntermediateCA, notAfterNext),
			subjectKeyIDToRevoke: deactivatedUpstreamAuthorityID,
			expectCode:           codes.Internal,
			expectMsg:            "failed to revoke X.509 upstream authority: it is not possible to revoke an untainted root CA",
			noTaintedKeys:        true,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to revoke X.509 upstream authority",
					Data: logrus.Fields{
						logrus.ErrorKey:        "rpc error: code = InvalidArgument desc = it is not possible to revoke an untainted root CA",
						telemetry.SubjectKeyID: deactivatedUpstreamAuthorityID,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to revoke X.509 upstream authority: it is not possible to revoke an untainted root CA",
						telemetry.Type:          "audit",
						telemetry.SubjectKeyID:  deactivatedUpstreamAuthorityID,
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
			test.ca.isUpstreamAuthority = !tt.isLocalAuthority

			_, err := test.ds.CreateBundle(ctx, &common.Bundle{
				TrustDomainId: serverTrustDomain.IDString(),
				RootCas: []*common.Certificate{
					{
						DerBytes: activeUpstreamAuthorityCert.Raw,
					},
					{
						DerBytes:   deactivatedUpstreamAuthorityCert.Raw,
						TaintedKey: !tt.noTaintedKeys,
					},
				},
			})
			require.NoError(t, err)

			resp, err := test.client.RevokeX509UpstreamAuthority(ctx, &localauthorityv1.RevokeX509UpstreamAuthorityRequest{
				SubjectKeyId: tt.subjectKeyIDToRevoke,
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

	test := &serviceTest{
		ds:      ds,
		logHook: logHook,
		ca:      m,
	}

	overrideContext := func(ctx context.Context) context.Context {
		return rpccontext.WithLogger(ctx, log)
	}

	server := grpctest.StartServer(t, func(s grpc.ServiceRegistrar) {
		localauthority.RegisterService(s, service)
	},
		grpctest.OverrideContext(overrideContext),
		grpctest.Middleware(middleware.WithAuditLog(false)),
	)

	conn := server.Dial(t)

	test.done = server.Stop
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

	currentJWTKeySlot  *fakeSlot
	nextJWTKeySlot     *fakeSlot
	rotateJWTKeyCalled bool

	prepareJWTKeyErr error

	prepareX509CAErr    error
	isUpstreamAuthority bool

	notifyTaintedExpectErr   error
	notifyTaintedAuthorityID string
}

func (m *fakeCAManager) NotifyTaintedX509Authority(ctx context.Context, authorityID string) error {
	if m.notifyTaintedExpectErr != nil {
		return m.notifyTaintedExpectErr
	}
	m.notifyTaintedAuthorityID = authorityID
	return nil
}

func (m *fakeCAManager) IsUpstreamAuthority() bool {
	return m.isUpstreamAuthority
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

func (m *fakeCAManager) RotateJWTKey(context.Context) {
	m.rotateJWTKeyCalled = true
}

func (m *fakeCAManager) GetCurrentX509CASlot() manager.Slot {
	return m.currentX509CASlot
}

func (m *fakeCAManager) GetNextX509CASlot() manager.Slot {
	return m.nextX509CASlot
}

func (m *fakeCAManager) PrepareX509CA(context.Context) error {
	return m.prepareX509CAErr
}

func (m *fakeCAManager) RotateX509CA(context.Context) {
	m.rotateX509CACalled = true
}

type fakeSlot struct {
	manager.Slot

	authorityID         string
	upstreamAuthorityID string
	notAfter            time.Time
	publicKey           crypto.PublicKey
	status              journal.Status
}

func (s *fakeSlot) UpstreamAuthorityID() string {
	return s.upstreamAuthorityID
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

func createSlotWithUpstream(status journal.Status, ca *testca.CA, notAfter time.Time) *fakeSlot {
	return &fakeSlot{
		authorityID:         ca.GetSubjectKeyID(),
		notAfter:            notAfter,
		status:              status,
		upstreamAuthorityID: ca.GetUpstreamAuthorityID(),
	}
}
