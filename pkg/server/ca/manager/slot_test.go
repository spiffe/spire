package manager

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/credtemplate"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/proto/private/server/journal"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/fakes/fakeserverkeymanager"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestX509CASlotShouldPrepareNext(t *testing.T) {
	clock := clock.NewMock()
	now := clock.Now()

	slot := &x509CASlot{
		id:       "A",
		issuedAt: clock.Now(),
		x509CA:   nil,
	}

	// No x509CA should not prepare next
	require.False(t, slot.ShouldPrepareNext(now.Add(-time.Hour)))

	// Adding certificate with expiration
	slot.x509CA = &ca.X509CA{
		Certificate: &x509.Certificate{
			NotAfter: now.Add(time.Minute),
		},
	}

	// Just created no need to prepare
	require.False(t, slot.ShouldPrepareNext(now))

	// Advance to before preparation time
	require.False(t, slot.ShouldPrepareNext(now.Add(30*time.Second)))

	// Advance to preparation time
	require.True(t, slot.ShouldPrepareNext(now.Add(31*time.Second)))
}

func TestX509CASlotShouldActivateNext(t *testing.T) {
	clock := clock.NewMock()
	now := clock.Now()

	slot := &x509CASlot{
		id:       "A",
		issuedAt: now,
		x509CA:   nil,
	}

	// No x509CA should not prepare next
	require.False(t, slot.ShouldActivateNext(now.Add(-time.Hour)))

	// Adding certificate with expiration
	slot.x509CA = &ca.X509CA{
		Certificate: &x509.Certificate{
			NotAfter: now.Add(time.Minute),
		},
	}

	// Just created no need to activate
	require.False(t, slot.ShouldActivateNext(now))

	// Advance to before preparation time
	require.False(t, slot.ShouldActivateNext(now.Add(50*time.Second)))

	// Advance to preparation time
	require.True(t, slot.ShouldActivateNext(now.Add(51*time.Second)))
}

func TestJWTKeySlotShouldPrepareNext(t *testing.T) {
	clock := clock.NewMock()
	now := clock.Now()

	slot := &jwtKeySlot{
		id:       "A",
		issuedAt: now,
		jwtKey:   nil,
	}

	// No jwt key, should prepare
	require.True(t, slot.ShouldPrepareNext(now.Add(time.Hour)))

	// Key is not ready to prepare
	slot.jwtKey = &ca.JWTKey{
		NotAfter: now.Add(time.Minute),
	}
	// Just created no need to prepare
	require.False(t, slot.ShouldPrepareNext(now))

	// Advance to before preparation time
	require.False(t, slot.ShouldPrepareNext(now.Add(30*time.Second)))

	// Advance to preparation time
	require.True(t, slot.ShouldPrepareNext(now.Add(31*time.Second)))
}

func TestJWTKeySlotShouldActivateNext(t *testing.T) {
	now := time.Now()

	slot := &jwtKeySlot{
		id:       "A",
		issuedAt: now,
		jwtKey:   nil,
	}

	// No jwt key, should activate
	require.True(t, slot.ShouldActivateNext(now.Add(time.Hour)))

	// Key is not ready to prepare
	slot.jwtKey = &ca.JWTKey{
		NotAfter: now.Add(time.Minute),
	}
	// Just created no need to prepare
	require.False(t, slot.ShouldActivateNext(now))

	// Advance to before activation time
	require.False(t, slot.ShouldActivateNext(now.Add(50*time.Second)))

	// Advance to preparation time
	require.True(t, slot.ShouldActivateNext(now.Add(51*time.Second)))
}

func TestWITKeySlotShouldPrepareNext(t *testing.T) {
	clock := clock.NewMock()
	now := clock.Now()

	slot := &witKeySlot{
		id:       "A",
		issuedAt: now,
		witKey:   nil,
	}

	// No wit key, should prepare
	require.True(t, slot.ShouldPrepareNext(now.Add(time.Hour)))

	// Key is not ready to prepare
	slot.witKey = &ca.WITKey{
		NotAfter: now.Add(time.Minute),
	}
	// Just created no need to prepare
	require.False(t, slot.ShouldPrepareNext(now))

	// Advance to before preparation time
	require.False(t, slot.ShouldPrepareNext(now.Add(30*time.Second)))

	// Advance to preparation time
	require.True(t, slot.ShouldPrepareNext(now.Add(31*time.Second)))
}

func TestWITKeySlotShouldActivateNext(t *testing.T) {
	now := time.Now()

	slot := &witKeySlot{
		id:       "A",
		issuedAt: now,
		witKey:   nil,
	}

	// No wit key, should activate
	require.True(t, slot.ShouldActivateNext(now.Add(time.Hour)))

	// Key is not ready to prepare
	slot.witKey = &ca.WITKey{
		NotAfter: now.Add(time.Minute),
	}
	// Just created no need to prepare
	require.False(t, slot.ShouldActivateNext(now))

	// Advance to before activation time
	require.False(t, slot.ShouldActivateNext(now.Add(50*time.Second)))

	// Advance to preparation time
	require.True(t, slot.ShouldActivateNext(now.Add(51*time.Second)))
}

func TestJournalLoad(t *testing.T) {
	ctx := context.Background()
	log, loghook := test.NewNullLogger()

	clk := clock.New()
	now := clk.Now()

	credBuilder, err := credtemplate.NewBuilder(credtemplate.Config{
		TrustDomain:   testTrustDomain,
		X509CASubject: pkix.Name{CommonName: "SPIRE"},
		Clock:         clk,
		X509CATTL:     testCATTL,
	})
	require.NoError(t, err)

	km := fakeserverkeymanager.New(t)
	ds := fakedatastore.New(t)
	td := spiffeid.RequireTrustDomainFromString("example.org")

	cat := fakeservercatalog.New()
	cat.SetKeyManager(km)
	cat.SetDataStore(ds)

	// Initializing key manager
	x509KeyA, x509RootA, err := createSelfSigned(ctx, credBuilder, km, "x509-CA-A")
	require.NoError(t, err)

	x509KeyB, x509RootB, err := createSelfSigned(ctx, credBuilder, km, "x509-CA-B")
	require.NoError(t, err)

	jwtKeyA, err := km.GenerateKey(ctx, "JWT-Signer-A", keymanager.ECP256)
	require.NoError(t, err)

	jwtKeyB, err := km.GenerateKey(ctx, "JWT-Signer-B", keymanager.ECP256)
	require.NoError(t, err)

	jwtKeyAPKIX, err := x509.MarshalPKIXPublicKey(jwtKeyA.Public())
	require.NoError(t, err)

	jwtKeyBPKIX, err := x509.MarshalPKIXPublicKey(jwtKeyB.Public())
	require.NoError(t, err)

	witKeyA, err := km.GenerateKey(ctx, "WIT-Signer-A", keymanager.ECP256)
	require.NoError(t, err)

	witKeyB, err := km.GenerateKey(ctx, "WIT-Signer-B", keymanager.ECP256)
	require.NoError(t, err)

	witKeyAPKIX, err := x509.MarshalPKIXPublicKey(witKeyA.Public())
	require.NoError(t, err)

	witKeyBPKIX, err := x509.MarshalPKIXPublicKey(witKeyB.Public())
	require.NoError(t, err)

	activeX509AuthorityID := getOneX509AuthorityID(ctx, t, km)

	// Dates
	firstIssuedAtUnix := now.Add(-3 * time.Minute).Unix()
	firstIssuedAt := time.Unix(firstIssuedAtUnix, 0)
	secondIssuedAtUnix := now.Add(-2 * time.Minute).Unix()
	secondIssuedAt := time.Unix(secondIssuedAtUnix, 0)
	thirdIssuedAtUnix := now.Add(-time.Minute).Unix()
	thirdIssuedAt := time.Unix(thirdIssuedAtUnix, 0)
	notAfterUnix := now.Add(time.Hour).Unix()
	notAfter := time.Unix(notAfterUnix, 0)

	_, expectParseErr := x509.ParsePKIXPublicKey([]byte("foo"))
	require.Error(t, expectParseErr)

	for _, tt := range []struct {
		name        string
		entries     *journal.Entries
		expectSlots map[SlotPosition]Slot
		expectError string
		expectLogs  []spiretest.LogEntry
	}{
		{
			name:    "Journal has no entries",
			entries: &journal.Entries{},
			expectSlots: map[SlotPosition]Slot{
				CurrentX509CASlot: &x509CASlot{id: "A"},
				NextX509CASlot:    &x509CASlot{id: "B"},
				CurrentJWTKeySlot: &jwtKeySlot{id: "A"},
				NextJWTKeySlot:    &jwtKeySlot{id: "B"},
				CurrentWITKeySlot: newWITKeySlot("A"),
				NextWITKeySlot:    newWITKeySlot("B"),
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Journal loaded",
					Data: logrus.Fields{
						telemetry.JWTKeys: "0",
						telemetry.X509CAs: "0",
						telemetry.WITKeys: "0",
					},
				},
			},
		},
		{
			name: "stored file has a single entry",
			entries: &journal.Entries{
				X509CAs: []*journal.X509CAEntry{
					{
						SlotId:      "B",
						NotAfter:    notAfterUnix,
						IssuedAt:    secondIssuedAtUnix,
						Certificate: x509RootB.Raw,
						Status:      journal.Status_ACTIVE,
					},
				},
				JwtKeys: []*journal.JWTKeyEntry{
					{
						SlotId:    "B",
						IssuedAt:  secondIssuedAtUnix,
						Kid:       "kid2",
						NotAfter:  notAfterUnix,
						PublicKey: jwtKeyBPKIX,
						Status:    journal.Status_ACTIVE,
					},
				},
				WitKeys: []*journal.WITKeyEntry{
					{
						SlotId:    "B",
						IssuedAt:  secondIssuedAtUnix,
						Kid:       "kid2",
						NotAfter:  notAfterUnix,
						PublicKey: witKeyBPKIX,
						Status:    journal.Status_ACTIVE,
					},
				},
			},
			expectSlots: map[SlotPosition]Slot{
				CurrentX509CASlot: &x509CASlot{
					id:       "B",
					issuedAt: secondIssuedAt,
					status:   journal.Status_ACTIVE,
					x509CA: &ca.X509CA{
						Signer:      x509KeyB,
						Certificate: x509RootB,
					},
					authorityID: "",
					publicKey:   x509KeyB.Public(),
					notAfter:    x509RootB.NotAfter,
				},
				NextX509CASlot: &x509CASlot{id: "A"},
				CurrentJWTKeySlot: &jwtKeySlot{
					id:       "B",
					issuedAt: secondIssuedAt,
					status:   journal.Status_ACTIVE,
					jwtKey: &ca.JWTKey{
						Signer:   jwtKeyB,
						Kid:      "kid2",
						NotAfter: notAfter,
					},
					authorityID: "",
					notAfter:    notAfter,
				},
				NextJWTKeySlot: &jwtKeySlot{id: "A"},
				CurrentWITKeySlot: &witKeySlot{
					id:       "B",
					issuedAt: secondIssuedAt,
					status:   journal.Status_ACTIVE,
					witKey: &ca.WITKey{
						Signer:   witKeyB,
						Kid:      "kid2",
						NotAfter: notAfter,
					},
					authorityID: "",
					notAfter:    notAfter,
				},
				NextWITKeySlot: newWITKeySlot("A"),
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Journal loaded",
					Data: logrus.Fields{
						telemetry.JWTKeys: "1",
						telemetry.X509CAs: "1",
						telemetry.WITKeys: "1",
					},
				},
			},
		},
		{
			name: "Stored entry has a single Prepared entry",
			entries: &journal.Entries{
				X509CAs: []*journal.X509CAEntry{
					{
						SlotId:      "A",
						IssuedAt:    thirdIssuedAtUnix,
						NotAfter:    notAfterUnix,
						Certificate: x509RootA.Raw,
						Status:      journal.Status_PREPARED,
						AuthorityId: "1",
					},
				},
				JwtKeys: []*journal.JWTKeyEntry{
					{
						SlotId:      "A",
						IssuedAt:    thirdIssuedAtUnix,
						Kid:         "kid3",
						NotAfter:    notAfterUnix,
						PublicKey:   jwtKeyAPKIX,
						Status:      journal.Status_PREPARED,
						AuthorityId: "a",
					},
				},
				WitKeys: []*journal.WITKeyEntry{
					{
						SlotId:      "A",
						IssuedAt:    thirdIssuedAtUnix,
						Kid:         "kid3",
						NotAfter:    notAfterUnix,
						PublicKey:   witKeyAPKIX,
						Status:      journal.Status_PREPARED,
						AuthorityId: "a",
					},
				},
			},
			expectSlots: map[SlotPosition]Slot{
				CurrentX509CASlot: &x509CASlot{
					id:       "A",
					issuedAt: thirdIssuedAt,
					status:   journal.Status_PREPARED,
					x509CA: &ca.X509CA{
						Signer:      x509KeyA,
						Certificate: x509RootA,
					},
					publicKey:   x509KeyA.Public(),
					authorityID: "1",
					notAfter:    x509RootA.NotAfter,
				},
				NextX509CASlot: &x509CASlot{
					id: "B",
				},
				CurrentJWTKeySlot: &jwtKeySlot{
					id:       "A",
					issuedAt: thirdIssuedAt,
					status:   journal.Status_PREPARED,
					jwtKey: &ca.JWTKey{
						Signer:   jwtKeyA,
						Kid:      "kid3",
						NotAfter: notAfter,
					},
					authorityID: "a",
					notAfter:    notAfter,
				},
				NextJWTKeySlot: &jwtKeySlot{
					id: "B",
				},
				CurrentWITKeySlot: &witKeySlot{
					id:       "A",
					issuedAt: thirdIssuedAt,
					status:   journal.Status_PREPARED,
					witKey: &ca.WITKey{
						Signer:   witKeyA,
						Kid:      "kid3",
						NotAfter: notAfter,
					},
					authorityID: "a",
					notAfter:    notAfter,
				},
				NextWITKeySlot: newWITKeySlot("B"),
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Journal loaded",
					Data: logrus.Fields{
						telemetry.JWTKeys: "1",
						telemetry.X509CAs: "1",
						telemetry.WITKeys: "1",
					},
				},
			},
		},
		{
			name: "Stored entries has old and active",
			entries: &journal.Entries{
				X509CAs: []*journal.X509CAEntry{
					{
						SlotId:      "A",
						IssuedAt:    firstIssuedAtUnix,
						NotAfter:    notAfterUnix,
						Certificate: x509RootA.Raw,
						Status:      journal.Status_OLD,
						AuthorityId: "3",
					},
					{
						SlotId:      "B",
						IssuedAt:    secondIssuedAtUnix,
						NotAfter:    notAfterUnix,
						Certificate: x509RootB.Raw,
						Status:      journal.Status_OLD,
						AuthorityId: "2",
					},
					{
						SlotId:      "A",
						IssuedAt:    thirdIssuedAtUnix,
						NotAfter:    notAfterUnix,
						Certificate: x509RootA.Raw,
						Status:      journal.Status_ACTIVE,
						AuthorityId: "1",
					},
				},
				JwtKeys: []*journal.JWTKeyEntry{
					{
						SlotId:      "A",
						IssuedAt:    firstIssuedAtUnix,
						Kid:         "kid1",
						NotAfter:    notAfterUnix,
						PublicKey:   jwtKeyAPKIX,
						Status:      journal.Status_OLD,
						AuthorityId: "c",
					},
					{
						SlotId:      "B",
						IssuedAt:    secondIssuedAtUnix,
						Kid:         "kid2",
						NotAfter:    notAfterUnix,
						PublicKey:   jwtKeyBPKIX,
						Status:      journal.Status_OLD,
						AuthorityId: "b",
					},
					{
						SlotId:      "A",
						IssuedAt:    thirdIssuedAtUnix,
						Kid:         "kid3",
						NotAfter:    notAfterUnix,
						PublicKey:   jwtKeyAPKIX,
						Status:      journal.Status_ACTIVE,
						AuthorityId: "a",
					},
				},
				WitKeys: []*journal.WITKeyEntry{
					{
						SlotId:      "A",
						IssuedAt:    firstIssuedAtUnix,
						Kid:         "kid1",
						NotAfter:    notAfterUnix,
						PublicKey:   witKeyAPKIX,
						Status:      journal.Status_OLD,
						AuthorityId: "c",
					},
					{
						SlotId:      "B",
						IssuedAt:    secondIssuedAtUnix,
						Kid:         "kid2",
						NotAfter:    notAfterUnix,
						PublicKey:   witKeyBPKIX,
						Status:      journal.Status_OLD,
						AuthorityId: "b",
					},
					{
						SlotId:      "A",
						IssuedAt:    thirdIssuedAtUnix,
						Kid:         "kid3",
						NotAfter:    notAfterUnix,
						PublicKey:   witKeyAPKIX,
						Status:      journal.Status_ACTIVE,
						AuthorityId: "a",
					},
				},
			},
			expectSlots: map[SlotPosition]Slot{
				CurrentX509CASlot: &x509CASlot{
					id:       "A",
					issuedAt: thirdIssuedAt,
					status:   journal.Status_ACTIVE,
					x509CA: &ca.X509CA{
						Signer:      x509KeyA,
						Certificate: x509RootA,
					},
					authorityID: "1",
					publicKey:   x509KeyA.Public(),
					notAfter:    x509RootA.NotAfter,
				},
				NextX509CASlot: &x509CASlot{
					id:       "B",
					issuedAt: secondIssuedAt,
					status:   journal.Status_OLD,
					x509CA: &ca.X509CA{
						Signer:      x509KeyB,
						Certificate: x509RootB,
					},
					authorityID: "2",
					publicKey:   x509KeyB.Public(),
					notAfter:    x509RootB.NotAfter,
				},
				CurrentJWTKeySlot: &jwtKeySlot{
					id:       "A",
					issuedAt: thirdIssuedAt,
					status:   journal.Status_ACTIVE,
					jwtKey: &ca.JWTKey{
						Signer:   jwtKeyA,
						Kid:      "kid3",
						NotAfter: notAfter,
					},
					authorityID: "a",
					notAfter:    notAfter,
				},
				NextJWTKeySlot: &jwtKeySlot{
					id:       "B",
					issuedAt: secondIssuedAt,
					status:   journal.Status_OLD,
					jwtKey: &ca.JWTKey{
						Signer:   jwtKeyB,
						Kid:      "kid2",
						NotAfter: notAfter,
					},
					authorityID: "b",
					notAfter:    notAfter,
				},
				CurrentWITKeySlot: &witKeySlot{
					id:       "A",
					issuedAt: thirdIssuedAt,
					status:   journal.Status_ACTIVE,
					witKey: &ca.WITKey{
						Signer:   witKeyA,
						Kid:      "kid3",
						NotAfter: notAfter,
					},
					authorityID: "a",
					notAfter:    notAfter,
				},
				NextWITKeySlot: &witKeySlot{
					id:       "B",
					issuedAt: secondIssuedAt,
					status:   journal.Status_OLD,
					witKey: &ca.WITKey{
						Signer:   witKeyB,
						Kid:      "kid2",
						NotAfter: notAfter,
					},
					authorityID: "b",
					notAfter:    notAfter,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Journal loaded",
					Data: logrus.Fields{
						telemetry.JWTKeys: "3",
						telemetry.X509CAs: "3",
						telemetry.WITKeys: "3",
					},
				},
			},
		},
		{
			name: "There are another entries before Active entry",
			entries: &journal.Entries{
				X509CAs: []*journal.X509CAEntry{
					// This can happen when force rotation is executed
					{
						SlotId:      "A",
						IssuedAt:    firstIssuedAtUnix,
						NotAfter:    notAfterUnix,
						Certificate: x509RootA.Raw,
						Status:      journal.Status_ACTIVE,
						AuthorityId: "3",
					},
					{
						SlotId:      "B",
						IssuedAt:    secondIssuedAtUnix,
						NotAfter:    notAfterUnix,
						Certificate: x509RootB.Raw,
						Status:      journal.Status_OLD,
						AuthorityId: "2",
					},
					{
						SlotId:      "B",
						IssuedAt:    thirdIssuedAtUnix,
						NotAfter:    notAfterUnix,
						Certificate: x509RootB.Raw,
						Status:      journal.Status_PREPARED,
						AuthorityId: "1",
					},
				},
				JwtKeys: []*journal.JWTKeyEntry{
					// This can happen when force rotation is executed
					{
						SlotId:      "A",
						IssuedAt:    firstIssuedAtUnix,
						Kid:         "kid1",
						NotAfter:    notAfterUnix,
						PublicKey:   jwtKeyAPKIX,
						Status:      journal.Status_ACTIVE,
						AuthorityId: "c",
					},
					{
						SlotId:      "B",
						IssuedAt:    secondIssuedAtUnix,
						Kid:         "kid2",
						NotAfter:    notAfterUnix,
						PublicKey:   jwtKeyBPKIX,
						Status:      journal.Status_OLD,
						AuthorityId: "b",
					},
					{
						SlotId:      "B",
						IssuedAt:    thirdIssuedAtUnix,
						Kid:         "kid3",
						NotAfter:    notAfterUnix,
						PublicKey:   jwtKeyBPKIX,
						Status:      journal.Status_PREPARED,
						AuthorityId: "a",
					},
				},
				WitKeys: []*journal.WITKeyEntry{
					// This can happen when force rotation is executed
					{
						SlotId:      "A",
						IssuedAt:    firstIssuedAtUnix,
						Kid:         "kid1",
						NotAfter:    notAfterUnix,
						PublicKey:   witKeyAPKIX,
						Status:      journal.Status_ACTIVE,
						AuthorityId: "c",
					},
					{
						SlotId:      "B",
						IssuedAt:    secondIssuedAtUnix,
						Kid:         "kid2",
						NotAfter:    notAfterUnix,
						PublicKey:   witKeyBPKIX,
						Status:      journal.Status_OLD,
						AuthorityId: "b",
					},
					{
						SlotId:      "B",
						IssuedAt:    thirdIssuedAtUnix,
						Kid:         "kid3",
						NotAfter:    notAfterUnix,
						PublicKey:   witKeyBPKIX,
						Status:      journal.Status_PREPARED,
						AuthorityId: "a",
					},
				},
			},
			expectSlots: map[SlotPosition]Slot{
				CurrentX509CASlot: &x509CASlot{
					id:       "A",
					issuedAt: firstIssuedAt,
					status:   journal.Status_ACTIVE,
					x509CA: &ca.X509CA{
						Signer:      x509KeyA,
						Certificate: x509RootA,
					},
					publicKey:   x509KeyA.Public(),
					authorityID: "3",
					notAfter:    x509RootA.NotAfter,
				},
				NextX509CASlot: &x509CASlot{
					id:       "B",
					issuedAt: thirdIssuedAt,
					status:   journal.Status_PREPARED,
					x509CA: &ca.X509CA{
						Signer:      x509KeyB,
						Certificate: x509RootB,
					},
					publicKey:   x509KeyB.Public(),
					authorityID: "1",
					notAfter:    x509RootB.NotAfter,
				},
				CurrentJWTKeySlot: &jwtKeySlot{
					id:       "A",
					issuedAt: firstIssuedAt,
					status:   journal.Status_ACTIVE,
					jwtKey: &ca.JWTKey{
						Signer:   jwtKeyA,
						Kid:      "kid1",
						NotAfter: notAfter,
					},
					authorityID: "c",
					notAfter:    notAfter,
				},
				NextJWTKeySlot: &jwtKeySlot{
					id:       "B",
					issuedAt: thirdIssuedAt,
					status:   journal.Status_PREPARED,
					jwtKey: &ca.JWTKey{
						Signer:   jwtKeyB,
						Kid:      "kid3",
						NotAfter: notAfter,
					},
					authorityID: "a",
					notAfter:    notAfter,
				},
				CurrentWITKeySlot: &witKeySlot{
					id:       "A",
					issuedAt: firstIssuedAt,
					status:   journal.Status_ACTIVE,
					witKey: &ca.WITKey{
						Signer:   witKeyA,
						Kid:      "kid1",
						NotAfter: notAfter,
					},
					authorityID: "c",
					notAfter:    notAfter,
				},
				NextWITKeySlot: &witKeySlot{
					id:       "B",
					issuedAt: thirdIssuedAt,
					status:   journal.Status_PREPARED,
					witKey: &ca.WITKey{
						Signer:   witKeyB,
						Kid:      "kid3",
						NotAfter: notAfter,
					},
					authorityID: "a",
					notAfter:    notAfter,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Journal loaded",
					Data: logrus.Fields{
						telemetry.JWTKeys: "3",
						telemetry.X509CAs: "3",
						telemetry.WITKeys: "3",
					},
				},
			},
		},
		{
			name: "Invalid X.509 entry",
			entries: &journal.Entries{
				X509CAs: []*journal.X509CAEntry{
					{
						SlotId:              "A",
						IssuedAt:            firstIssuedAtUnix,
						NotAfter:            notAfterUnix,
						Certificate:         []byte("foo"),
						Status:              journal.Status_ACTIVE,
						AuthorityId:         "1",
						UpstreamAuthorityId: "2",
					},
				},
			},
			expectError: "unable to parse CA certificate: x509: malformed certificate",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Journal loaded",
					Data: logrus.Fields{
						telemetry.X509CAs: "1",
						telemetry.JWTKeys: "0",
						telemetry.WITKeys: "0",
					},
				},
				{
					Level:   logrus.ErrorLevel,
					Message: "X509CA slot failed to load",
					Data: logrus.Fields{
						logrus.ErrorKey:               "unable to parse CA certificate: x509: malformed certificate",
						telemetry.IssuedAt:            firstIssuedAt.String(),
						telemetry.Slot:                "A",
						telemetry.Status:              "ACTIVE",
						telemetry.LocalAuthorityID:    "1",
						telemetry.UpstreamAuthorityID: "2",
					},
				},
			},
		},
		{
			name: "Expired X.509 entry",
			entries: &journal.Entries{
				X509CAs: []*journal.X509CAEntry{
					{
						SlotId:              "A",
						IssuedAt:            firstIssuedAtUnix,
						NotAfter:            time.Now().Add(-time.Minute).Unix(),
						Certificate:         x509RootA.Raw,
						Status:              journal.Status_ACTIVE,
						AuthorityId:         "1",
						UpstreamAuthorityId: "2",
					},
				},
			},
			expectSlots: map[SlotPosition]Slot{
				CurrentX509CASlot: newX509CASlot("A"),
				NextX509CASlot:    newX509CASlot("B"),
				CurrentJWTKeySlot: newJWTKeySlot("A"),
				NextJWTKeySlot:    newJWTKeySlot("B"),
				CurrentWITKeySlot: newWITKeySlot("A"),
				NextWITKeySlot:    newWITKeySlot("B"),
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Journal loaded",
					Data: logrus.Fields{
						telemetry.X509CAs: "1",
						telemetry.JWTKeys: "0",
						telemetry.WITKeys: "0",
					},
				},
				{
					Level:   logrus.WarnLevel,
					Message: "X509CA slot unusable",
					Data: logrus.Fields{
						logrus.ErrorKey:               "slot expired",
						telemetry.IssuedAt:            firstIssuedAt.String(),
						telemetry.Slot:                "A",
						telemetry.Status:              "ACTIVE",
						telemetry.LocalAuthorityID:    "1",
						telemetry.UpstreamAuthorityID: "2",
					},
				},
			},
		},
		{
			name: "Invalid JWTKey entry",
			entries: &journal.Entries{
				JwtKeys: []*journal.JWTKeyEntry{
					{
						SlotId:      "B",
						IssuedAt:    thirdIssuedAtUnix,
						Kid:         "kid3",
						NotAfter:    notAfterUnix,
						PublicKey:   []byte("foo"),
						Status:      journal.Status_PREPARED,
						AuthorityId: "a",
					},
				},
			},
			expectError: expectParseErr.Error(),
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Journal loaded",
					Data: logrus.Fields{
						telemetry.X509CAs: "0",
						telemetry.JWTKeys: "1",
						telemetry.WITKeys: "0",
					},
				},
				{
					Level:   logrus.ErrorLevel,
					Message: "JWT key slot failed to load",
					Data: logrus.Fields{
						logrus.ErrorKey:            expectParseErr.Error(),
						telemetry.Slot:             "B",
						telemetry.IssuedAt:         thirdIssuedAt.String(),
						telemetry.Status:           "PREPARED",
						telemetry.LocalAuthorityID: "a",
					},
				},
			},
		},
		{
			name: "Expired JWTKey entry",
			entries: &journal.Entries{
				JwtKeys: []*journal.JWTKeyEntry{
					{
						SlotId:      "B",
						IssuedAt:    thirdIssuedAtUnix,
						Kid:         "kid3",
						NotAfter:    time.Now().Add(-time.Minute).Unix(),
						PublicKey:   jwtKeyAPKIX,
						Status:      journal.Status_ACTIVE,
						AuthorityId: "a",
					},
				},
			},
			expectSlots: map[SlotPosition]Slot{
				CurrentX509CASlot: newX509CASlot("A"),
				NextX509CASlot:    newX509CASlot("B"),
				CurrentJWTKeySlot: newJWTKeySlot("A"),
				NextJWTKeySlot:    newJWTKeySlot("B"),
				CurrentWITKeySlot: newWITKeySlot("A"),
				NextWITKeySlot:    newWITKeySlot("B"),
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Journal loaded",
					Data: logrus.Fields{
						telemetry.X509CAs: "0",
						telemetry.JWTKeys: "1",
						telemetry.WITKeys: "0",
					},
				},
				{
					Level:   logrus.WarnLevel,
					Message: "JWT key slot unusable",
					Data: logrus.Fields{
						logrus.ErrorKey:            "slot expired",
						telemetry.IssuedAt:         thirdIssuedAt.String(),
						telemetry.Slot:             "B",
						telemetry.Status:           "ACTIVE",
						telemetry.LocalAuthorityID: "a",
					},
				},
			},
		},
		{
			name: "Invalid WITKey entry",
			entries: &journal.Entries{
				WitKeys: []*journal.WITKeyEntry{
					{
						SlotId:      "B",
						IssuedAt:    thirdIssuedAtUnix,
						Kid:         "kid3",
						NotAfter:    notAfterUnix,
						PublicKey:   []byte("foo"),
						Status:      journal.Status_PREPARED,
						AuthorityId: "a",
					},
				},
			},
			expectError: expectParseErr.Error(),
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Journal loaded",
					Data: logrus.Fields{
						telemetry.X509CAs: "0",
						telemetry.JWTKeys: "0",
						telemetry.WITKeys: "1",
					},
				},
				{
					Level:   logrus.ErrorLevel,
					Message: "WIT key slot failed to load",
					Data: logrus.Fields{
						logrus.ErrorKey:            expectParseErr.Error(),
						telemetry.Slot:             "B",
						telemetry.IssuedAt:         thirdIssuedAt.String(),
						telemetry.Status:           "PREPARED",
						telemetry.LocalAuthorityID: "a",
					},
				},
			},
		},
		{
			name: "Expired WITKey entry",
			entries: &journal.Entries{
				WitKeys: []*journal.WITKeyEntry{
					{
						SlotId:      "B",
						IssuedAt:    thirdIssuedAtUnix,
						Kid:         "kid3",
						NotAfter:    time.Now().Add(-time.Minute).Unix(),
						PublicKey:   witKeyAPKIX,
						Status:      journal.Status_ACTIVE,
						AuthorityId: "a",
					},
				},
			},
			expectSlots: map[SlotPosition]Slot{
				CurrentX509CASlot: newX509CASlot("A"),
				NextX509CASlot:    newX509CASlot("B"),
				CurrentJWTKeySlot: newJWTKeySlot("A"),
				NextJWTKeySlot:    newJWTKeySlot("B"),
				CurrentWITKeySlot: newWITKeySlot("A"),
				NextWITKeySlot:    newWITKeySlot("B"),
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Journal loaded",
					Data: logrus.Fields{
						telemetry.X509CAs: "0",
						telemetry.JWTKeys: "0",
						telemetry.WITKeys: "1",
					},
				},
				{
					Level:   logrus.WarnLevel,
					Message: "WIT key slot unusable",
					Data: logrus.Fields{
						logrus.ErrorKey:            "slot expired",
						telemetry.IssuedAt:         thirdIssuedAt.String(),
						telemetry.Slot:             "B",
						telemetry.Status:           "ACTIVE",
						telemetry.LocalAuthorityID: "a",
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			loghook.Reset()
			journal := new(Journal)
			journal.config = &journalConfig{
				cat: cat,
				log: log,
			}
			journal.setEntries(tt.entries)
			journal.activeX509AuthorityID = activeX509AuthorityID
			err = journal.save(ctx)
			require.NoError(t, err)

			loader := &SlotLoader{
				TrustDomain: td,
				Log:         log,
				Catalog:     cat,
			}

			loadedJournal, slots, err := loader.load(ctx)
			spiretest.AssertLastLogs(t, loghook.AllEntries(), tt.expectLogs)
			if tt.expectError != "" {
				spiretest.AssertErrorPrefix(t, err, tt.expectError)
				assert.Nil(t, loadedJournal)
				assert.Nil(t, slots)
				return
			}
			require.NoError(t, err)

			spiretest.AssertProtoEqual(t, tt.entries, loadedJournal.entries)
			require.Equal(t, tt.expectSlots, slots)
		})
	}
}

func createSelfSigned(ctx context.Context, credBuilder *credtemplate.Builder, km keymanager.KeyManager, id string) (keymanager.Key, *x509.Certificate, error) {
	key, err := km.GenerateKey(ctx, id, keymanager.ECP256)
	if err != nil {
		return nil, nil, err
	}

	templateA, err := credBuilder.BuildSelfSignedX509CATemplate(ctx, credtemplate.SelfSignedX509CAParams{
		PublicKey: key.Public(),
	})
	if err != nil {
		return nil, nil, err
	}

	root, err := x509util.CreateCertificate(templateA, templateA, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}

	return key, root, nil
}
