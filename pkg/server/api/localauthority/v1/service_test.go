package localauthority_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
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
	keyARaw, _        = x509.MarshalPKIXPublicKey(keyA.Public())
	keyBRaw, _        = x509.MarshalPKIXPublicKey(keyB.Public())
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
			currentSlot: createSlot(true, keyA.Public()),
			nextSlot:    &fakeSlot{},
			expectResp: &localauthorityv1.GetX509AuthorityStateResponse{
				States: []*localauthorityv1.AuthorityState{
					{
						PublicKey: keyARaw,
						Status:    localauthorityv1.AuthorityState_ACTIVE,
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
			nextSlot:    createSlot(true, keyB.Public()),
			expectResp: &localauthorityv1.GetX509AuthorityStateResponse{
				States: []*localauthorityv1.AuthorityState{
					{
						PublicKey: keyBRaw,
						Status:    localauthorityv1.AuthorityState_PREPARED,
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
			currentSlot: createSlot(true, keyA.Public()),
			nextSlot:    createSlot(false, keyB.Public()),
			expectResp: &localauthorityv1.GetX509AuthorityStateResponse{
				States: []*localauthorityv1.AuthorityState{
					{
						PublicKey: keyARaw,
						Status:    localauthorityv1.AuthorityState_ACTIVE,
					},
					{
						PublicKey: keyBRaw,
						Status:    localauthorityv1.AuthorityState_OLD,
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
			currentSlot: createSlot(true, nil),
			nextSlot:    &fakeSlot{},
			expectCode:  codes.Internal,
			expectMsg:   "failed to get current slot: slot does not have a public key",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to get current slot",
					Data: logrus.Fields{
						logrus.ErrorKey: "slot does not have a public key",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to get current slot: slot does not have a public key",
						telemetry.Type:          "audit",
					},
				},
			},
		},
		{
			name:        "current slot has invalid key",
			currentSlot: createSlot(true, keyA),
			nextSlot:    &fakeSlot{},
			expectCode:  codes.Internal,
			expectMsg:   "failed to get current slot: x509: unsupported public key type: *ecdsa.PrivateKey",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to get current slot",
					Data: logrus.Fields{
						logrus.ErrorKey: "x509: unsupported public key type: *ecdsa.PrivateKey",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to get current slot: x509: unsupported public key type: *ecdsa.PrivateKey",
						telemetry.Type:          "audit",
					},
				},
			},
		},
		{
			name:        "next slot has invalid key",
			currentSlot: createSlot(true, keyA.Public()),
			nextSlot:    createSlot(true, keyB),
			expectCode:  codes.Internal,
			expectMsg:   "failed to get next slot: x509: unsupported public key type: *ecdsa.PrivateKey",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to get next slot",
					Data: logrus.Fields{
						logrus.ErrorKey: "x509: unsupported public key type: *ecdsa.PrivateKey",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to get next slot: x509: unsupported public key type: *ecdsa.PrivateKey",
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
			nextSlot: createSlot(true, keyB.Public()),
			expectResp: &localauthorityv1.PrepareX509AuthorityResponse{
				PreparedAuthority: &localauthorityv1.AuthorityState{
					Status:    localauthorityv1.AuthorityState_PREPARED,
					PublicKey: keyBRaw,
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
			currentSlot: createSlot(true, keyA.Public()),
			nextSlot:    createSlot(false, keyB.Public()),
			expectResp: &localauthorityv1.PrepareX509AuthorityResponse{
				PreparedAuthority: &localauthorityv1.AuthorityState{
					Status:    localauthorityv1.AuthorityState_PREPARED,
					PublicKey: keyARaw,
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
			nextSlot:   createSlot(true, keyB.Public()),
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
		{
			name:       "slot contains invalid key",
			nextSlot:   createSlot(true, keyB),
			expectCode: codes.Internal,
			expectMsg:  "failed to create response: x509: unsupported public key type: *ecdsa.PrivateKey",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to create response",
					Data: logrus.Fields{
						logrus.ErrorKey: "x509: unsupported public key type: *ecdsa.PrivateKey",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to create response: x509: unsupported public key type: *ecdsa.PrivateKey",
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

		rotateCalled bool
		expectLogs   []spiretest.LogEntry
		expectCode   codes.Code
		expectMsg    string
		expectResp   *localauthorityv1.ActivateX509AuthorityResponse
	}{
		{
			name:         "activate successfully",
			currentSlot:  createSlot(true, keyA.Public()),
			nextSlot:     createSlot(true, keyB.Public()),
			rotateCalled: true,
			expectResp: &localauthorityv1.ActivateX509AuthorityResponse{
				ActivatedAuthority: &localauthorityv1.AuthorityState{
					Status:    localauthorityv1.AuthorityState_ACTIVE,
					PublicKey: keyARaw,
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
			name:        "next slot is not set",
			currentSlot: createSlot(true, keyA.Public()),
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
		{
			name:         "current slot return invalid key",
			currentSlot:  createSlot(true, keyA),
			nextSlot:     createSlot(true, keyB.Public()),
			rotateCalled: true,
			expectCode:   codes.Internal,
			expectMsg:    "failed to parse current slot: x509: unsupported public key type: *ecdsa.PrivateKey",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to parse current slot",
					Data: logrus.Fields{
						logrus.ErrorKey: "x509: unsupported public key type: *ecdsa.PrivateKey",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to parse current slot: x509: unsupported public key type: *ecdsa.PrivateKey",
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

			resp, err := test.client.ActivateX509Authority(ctx, &localauthorityv1.ActivateX509AuthorityRequest{})

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
	currentKeyRaw, err := x509.MarshalPKIXPublicKey(currentKey.Public())
	require.NoError(t, err)
	currentKeySHA256 := api.HashByte(currentKeyRaw)

	nextCA, nextKey, err := testutil.SelfSign(template)
	require.NoError(t, err)
	nextKeyRaw, err := x509.MarshalPKIXPublicKey(nextKey.Public())
	require.NoError(t, err)

	oldCA, oldKey, err := testutil.SelfSign(template)
	require.NoError(t, err)
	oldKeyRaw, err := x509.MarshalPKIXPublicKey(oldKey.Public())
	require.NoError(t, err)
	oldKeySHA256 := api.HashByte(oldKeyRaw)

	invalidKeyByte := []byte("foo")
	invalidKeySHA256 := api.HashByte(invalidKeyByte)
	_, invalidKeyErr := x509.ParsePKIXPublicKey(invalidKeyByte)
	require.Error(t, invalidKeyErr)

	noPersistedKeyRaw, err := x509.MarshalPKIXPublicKey(keyA.Public())
	require.NoError(t, err)
	noPersistedKeySHA256 := api.HashByte(noPersistedKeyRaw)

	for _, tt := range []struct {
		name        string
		currentSlot *fakeSlot
		nextSlot    *fakeSlot
		keyToTaint  []byte

		expectKeyToTaint crypto.PublicKey
		expectLogs       []spiretest.LogEntry
		expectCode       codes.Code
		expectMsg        string
		expectResp       *localauthorityv1.TaintX509AuthorityResponse
	}{
		{
			name:        "taint old authority",
			currentSlot: createSlot(true, currentKey.Public()),
			nextSlot:    createSlot(false, nextKey.Public()),
			expectResp: &localauthorityv1.TaintX509AuthorityResponse{
				TaintedAuthority: &localauthorityv1.AuthorityState{
					Status:    localauthorityv1.AuthorityState_OLD,
					PublicKey: nextKeyRaw,
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
					Message: "Key tainted successfully",
				},
			},
		},
		{
			name:        "taint authority from parameter",
			currentSlot: createSlot(true, currentKey.Public()),
			nextSlot:    createSlot(false, nextKey.Public()),
			keyToTaint:  oldKeyRaw,
			expectResp: &localauthorityv1.TaintX509AuthorityResponse{
				TaintedAuthority: &localauthorityv1.AuthorityState{
					Status:    localauthorityv1.AuthorityState_OLD,
					PublicKey: oldKeyRaw,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:                       "success",
						telemetry.Type:                         "audit",
						telemetry.X509AuthorityPublicKeySHA256: oldKeySHA256,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "Key tainted successfully",
				},
			},
		},
		{
			name:        "no allow to taint a prepared key",
			currentSlot: createSlot(true, currentKey.Public()),
			nextSlot:    createSlot(true, nextKey.Public()),
			expectCode:  codes.InvalidArgument,
			expectMsg:   "invalid public key: unable to use a prepared key",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid public key",
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
						telemetry.StatusMessage: "invalid public key: unable to use a prepared key",
						telemetry.Type:          "audit",
					},
				},
			},
		},
		{
			name:        "invalid key",
			currentSlot: createSlot(true, currentKey.Public()),
			nextSlot:    createSlot(false, nextKey.Public()),
			keyToTaint:  invalidKeyByte,
			expectCode:  codes.InvalidArgument,
			expectMsg:   "invalid public key: unable to parse public key: asn1: structure error:",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid public key",
					Data: logrus.Fields{
						logrus.ErrorKey: fmt.Sprintf("unable to parse public key: %v", invalidKeyErr),
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:                       "error",
						telemetry.StatusCode:                   "InvalidArgument",
						telemetry.StatusMessage:                fmt.Sprintf("invalid public key: unable to parse public key: %v", invalidKeyErr),
						telemetry.Type:                         "audit",
						telemetry.X509AuthorityPublicKeySHA256: invalidKeySHA256,
					},
				},
			},
		},
		{
			name:        "unable to taint current key",
			currentSlot: createSlot(true, currentKey.Public()),
			nextSlot:    createSlot(false, nextKey.Public()),
			keyToTaint:  currentKeyRaw,
			expectCode:  codes.InvalidArgument,
			expectMsg:   "invalid public key: unable to use current authority",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid public key",
					Data: logrus.Fields{
						logrus.ErrorKey: "unable to use current authority",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:                       "error",
						telemetry.StatusCode:                   "InvalidArgument",
						telemetry.StatusMessage:                "invalid public key: unable to use current authority",
						telemetry.Type:                         "audit",
						telemetry.X509AuthorityPublicKeySHA256: currentKeySHA256,
					},
				},
			},
		},
		{
			name:        "ds fails to taint",
			currentSlot: createSlot(true, currentKey.Public()),
			nextSlot:    createSlot(false, nextKey.Public()),
			keyToTaint:  noPersistedKeyRaw,
			expectCode:  codes.Internal,
			expectMsg:   "failed to taint X.509 authority: no root CA found with provided public key",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to taint X.509 authority",
					Data: logrus.Fields{
						logrus.ErrorKey: "rpc error: code = NotFound desc = no root CA found with provided public key",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:                       "error",
						telemetry.StatusCode:                   "Internal",
						telemetry.StatusMessage:                "failed to taint X.509 authority: no root CA found with provided public key",
						telemetry.Type:                         "audit",
						telemetry.X509AuthorityPublicKeySHA256: noPersistedKeySHA256,
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
				PublicKey: tt.keyToTaint,
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
	currentKeyRaw, err := x509.MarshalPKIXPublicKey(currentKey.Public())
	require.NoError(t, err)
	currentKeySHA256 := api.HashByte(currentKeyRaw)

	nextCA, nextKey, err := testutil.SelfSign(template)
	require.NoError(t, err)
	nextKeyRaw, err := x509.MarshalPKIXPublicKey(nextKey.Public())
	require.NoError(t, err)

	oldCA, oldKey, err := testutil.SelfSign(template)
	require.NoError(t, err)
	oldKeyRaw, err := x509.MarshalPKIXPublicKey(oldKey.Public())
	require.NoError(t, err)
	oldKeySHA256 := api.HashByte(oldKeyRaw)

	invalidKeyByte := []byte("foo")
	invalidKeySHA256 := api.HashByte(invalidKeyByte)
	_, invalidKeyErr := x509.ParsePKIXPublicKey(invalidKeyByte)
	require.Error(t, invalidKeyErr)

	noPersistedKeyRaw, err := x509.MarshalPKIXPublicKey(keyA.Public())
	require.NoError(t, err)
	noPersistedKeySHA256 := api.HashByte(noPersistedKeyRaw)

	for _, tt := range []struct {
		name        string
		currentSlot *fakeSlot
		nextSlot    *fakeSlot
		keyToRevoke []byte

		expectKeyToTaint crypto.PublicKey
		expectLogs       []spiretest.LogEntry
		expectCode       codes.Code
		expectMsg        string
		expectResp       *localauthorityv1.RevokeX509AuthorityResponse
	}{
		{
			name:        "revoke old authority",
			currentSlot: createSlot(true, currentKey.Public()),
			nextSlot:    createSlot(false, nextKey.Public()),
			expectResp: &localauthorityv1.RevokeX509AuthorityResponse{
				RevokedAuthority: &localauthorityv1.AuthorityState{
					Status:    localauthorityv1.AuthorityState_OLD,
					PublicKey: nextKeyRaw,
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
					Message: "Key revoked successfully",
				},
			},
		},
		{
			name:        "revoke authority from parameter",
			currentSlot: createSlot(true, currentKey.Public()),
			nextSlot:    createSlot(false, nextKey.Public()),
			keyToRevoke: oldKeyRaw,
			expectResp: &localauthorityv1.RevokeX509AuthorityResponse{
				RevokedAuthority: &localauthorityv1.AuthorityState{
					Status:    localauthorityv1.AuthorityState_OLD,
					PublicKey: oldKeyRaw,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:                       "success",
						telemetry.Type:                         "audit",
						telemetry.X509AuthorityPublicKeySHA256: oldKeySHA256,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "Key revoked successfully",
				},
			},
		},
		{
			name:        "no allow to revoke a prepared key",
			currentSlot: createSlot(true, currentKey.Public()),
			nextSlot:    createSlot(true, nextKey.Public()),
			expectCode:  codes.InvalidArgument,
			expectMsg:   "invalid public key: unable to use a prepared key",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid public key",
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
						telemetry.StatusMessage: "invalid public key: unable to use a prepared key",
						telemetry.Type:          "audit",
					},
				},
			},
		},
		{
			name:        "invalid key",
			currentSlot: createSlot(true, currentKey.Public()),
			nextSlot:    createSlot(false, nextKey.Public()),
			keyToRevoke: invalidKeyByte,
			expectCode:  codes.InvalidArgument,
			expectMsg:   "invalid public key: unable to parse public key: asn1:",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid public key",
					Data: logrus.Fields{
						logrus.ErrorKey: fmt.Sprintf("unable to parse public key: %v", invalidKeyErr),
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:                       "error",
						telemetry.StatusCode:                   "InvalidArgument",
						telemetry.StatusMessage:                fmt.Sprintf("invalid public key: unable to parse public key: %v", invalidKeyErr),
						telemetry.Type:                         "audit",
						telemetry.X509AuthorityPublicKeySHA256: invalidKeySHA256,
					},
				},
			},
		},
		{
			name:        "unable to revoke current key",
			currentSlot: createSlot(true, currentKey.Public()),
			nextSlot:    createSlot(false, nextKey.Public()),
			keyToRevoke: currentKeyRaw,
			expectCode:  codes.InvalidArgument,
			expectMsg:   "invalid public key: unable to use current authority",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid public key",
					Data: logrus.Fields{
						logrus.ErrorKey: "unable to use current authority",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:                       "error",
						telemetry.StatusCode:                   "InvalidArgument",
						telemetry.StatusMessage:                "invalid public key: unable to use current authority",
						telemetry.Type:                         "audit",
						telemetry.X509AuthorityPublicKeySHA256: currentKeySHA256,
					},
				},
			},
		},
		{
			name:        "ds fails to revoke",
			currentSlot: createSlot(true, currentKey.Public()),
			nextSlot:    createSlot(false, nextKey.Public()),
			keyToRevoke: noPersistedKeyRaw,
			expectCode:  codes.Internal,
			expectMsg:   "failed to revoke X.509 authority: no root CA found with provided public key",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to revoke X.509 authority",
					Data: logrus.Fields{
						logrus.ErrorKey: "rpc error: code = NotFound desc = no root CA found with provided public key",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:                       "error",
						telemetry.StatusCode:                   "Internal",
						telemetry.StatusMessage:                "failed to revoke X.509 authority: no root CA found with provided public key",
						telemetry.Type:                         "audit",
						telemetry.X509AuthorityPublicKeySHA256: noPersistedKeySHA256,
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
				PublicKey: tt.keyToRevoke,
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

	hasValue  bool
	publicKey crypto.PublicKey
}

func (s *fakeSlot) IsEmpty() bool {
	return !s.hasValue
}

func (s *fakeSlot) GetPublicKey() crypto.PublicKey {
	return s.publicKey
}

func createSlot(hasValue bool, publicKey crypto.PublicKey) *fakeSlot {
	return &fakeSlot{
		hasValue:  hasValue,
		publicKey: publicKey,
	}
}
