package rotator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/server/ca/manager"
	"github.com/spiffe/spire/proto/private/server/journal"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakehealthchecker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRotator(t *testing.T) {
	fakeHealthChecker := fakehealthchecker.New()
	rotator := NewRotator(Config{
		Manager:       &fakeCAManager{},
		HealthChecker: fakeHealthChecker,
	})

	require.NotNil(t, rotator)
	require.NotNil(t, rotator.c)
	require.NotNil(t, rotator.c.Clock)
}

func TestHealthChecks(t *testing.T) {
	test := setupTest(t)

	expectStateMap := map[string]health.State{
		"server.ca.rotator": {
			Live:         true,
			Ready:        true,
			ReadyDetails: managerHealthDetails{},
			LiveDetails:  managerHealthDetails{},
		},
	}
	require.Equal(t, expectStateMap, test.healthChecker.RunChecks())

	// update failed rotations to force healthcheck to fail
	test.rotator.failedRotationNum = failedRotationThreshold + 1
	expectStateMap = map[string]health.State{
		"server.ca.rotator": {
			Live:  false,
			Ready: false,
			ReadyDetails: managerHealthDetails{
				RotationErr: "rotations exceed the threshold number of failures",
			},
			LiveDetails: managerHealthDetails{
				RotationErr: "rotations exceed the threshold number of failures",
			},
		},
	}
	require.Equal(t, expectStateMap, test.healthChecker.RunChecks())
}

func TestInitialize(t *testing.T) {
	for _, tt := range []struct {
		name             string
		expectError      string
		hasCurrent       bool
		hasNext          bool
		prepareJWTKeyErr error
		prepareX509CAErr error

		expectCurrentX509CAID string
		expectCurrentJWTKeyID string
		moveToPrepare         bool
		moveToActivate        bool
	}{
		{
			name:                  "current authorities already exists",
			hasCurrent:            true,
			expectCurrentJWTKeyID: "jwt-a",
			expectCurrentX509CAID: "x509-a",
		},
		{
			name:             "failed to prepare current X509CA",
			expectError:      "oh no",
			prepareX509CAErr: errors.New("oh no"),
		},
		{
			name:             "failed to prepare current JWT Key",
			expectError:      "oh no",
			prepareJWTKeyErr: errors.New("oh no"),
		},
		{
			name:                  "prepare and activate current when does not exist",
			expectCurrentJWTKeyID: "jwt-a",
			expectCurrentX509CAID: "x509-a",
		},
		{
			name:                  "prepare and activate current when does not exist",
			expectCurrentJWTKeyID: "jwt-a",
			expectCurrentX509CAID: "x509-a",
		},
		{
			name:                  "prepare next",
			hasCurrent:            true,
			expectCurrentJWTKeyID: "jwt-a",
			expectCurrentX509CAID: "x509-a",
			moveToPrepare:         true,
		},
		{
			name:             "failed to prepare next X509CA",
			hasCurrent:       true,
			expectError:      "oh no",
			prepareX509CAErr: errors.New("oh no"),
			moveToPrepare:    true,
		},
		{
			name:             "failed to prepare next JWT Key",
			hasCurrent:       true,
			expectError:      "oh no",
			prepareJWTKeyErr: errors.New("oh no"),
			moveToPrepare:    true,
		},
		{
			name:                  "activate next",
			hasCurrent:            true,
			expectCurrentJWTKeyID: "jwt-b",
			expectCurrentX509CAID: "x509-b",
			moveToActivate:        true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t)

			now := test.clock.Now()
			test.fakeCAManager.currentJWTKeySlot = createSlot("jwt-a", now, tt.hasCurrent)
			test.fakeCAManager.currentX509CASlot = createSlot("x509-a", now, tt.hasCurrent)
			test.fakeCAManager.nextJWTKeySlot = createSlot("jwt-b", now, tt.hasNext)
			test.fakeCAManager.nextX509CASlot = createSlot("x509-b", now, tt.hasNext)
			test.fakeCAManager.prepareJWTKeyErr = tt.prepareJWTKeyErr
			test.fakeCAManager.prepareX509CAErr = tt.prepareX509CAErr

			switch {
			case tt.moveToPrepare:
				test.clock.Add(time.Minute + time.Second)
			case tt.moveToActivate:
				test.clock.Add(2*time.Minute + time.Second)
			}

			err := test.rotator.Initialize(context.Background())

			if tt.expectError != "" {
				require.EqualError(t, err, tt.expectError)
				return
			}
			require.NoError(t, err)

			require.Equal(t, tt.expectCurrentJWTKeyID, test.fakeCAManager.currentJWTKeySlot.KmKeyID())
			require.Equal(t, tt.expectCurrentX509CAID, test.fakeCAManager.currentX509CASlot.KmKeyID())
			require.True(t, test.fakeCAManager.currentX509CASlot.isActive)
			require.True(t, test.fakeCAManager.currentJWTKeySlot.isActive)

			if tt.moveToPrepare {
				require.False(t, test.fakeCAManager.nextX509CASlot.IsEmpty())
				require.False(t, test.fakeCAManager.nextJWTKeySlot.IsEmpty())
			} else {
				require.True(t, test.fakeCAManager.nextX509CASlot.IsEmpty())
				require.True(t, test.fakeCAManager.nextJWTKeySlot.IsEmpty())
			}
		})
	}
}

func TestRunNotifyBundleFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	test := setupTest(t)
	test.fakeCAManager.notifyBundleLoadedErr = errors.New("oh no")

	err := test.rotator.Run(ctx)
	require.EqualError(t, err, "oh no")
}

func TestRunJWTKeyRotation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	test := setupTest(t)

	go func() {
		err := test.rotator.Run(ctx)
		assert.NoError(t, err)
	}()

	require.Equal(t, "jwt-a", test.fakeCAManager.currentJWTKeySlot.keyID)
	require.True(t, test.fakeCAManager.currentJWTKeySlot.isActive)
	// No next prepared
	require.True(t, test.fakeCAManager.nextJWTKeySlot.IsEmpty())

	// Move to preparation mark nothing should change
	test.clock.Add(time.Minute)

	require.Equal(t, "jwt-a", test.fakeCAManager.currentJWTKeySlot.keyID)
	require.True(t, test.fakeCAManager.currentJWTKeySlot.isActive)
	require.Equal(t, "jwt-b", test.fakeCAManager.nextJWTKeySlot.keyID)
	require.True(t, test.fakeCAManager.nextJWTKeySlot.IsEmpty())

	// Move after preparation mark
	test.clock.Add(30 * time.Second)

	test.fakeCAManager.waitJWTKeyUpdate(ctx, t)

	require.Equal(t, "jwt-a", test.fakeCAManager.currentJWTKeySlot.keyID)
	require.True(t, test.fakeCAManager.currentJWTKeySlot.isActive)
	require.Equal(t, "jwt-b", test.fakeCAManager.nextJWTKeySlot.keyID)
	require.False(t, test.fakeCAManager.nextJWTKeySlot.IsEmpty())

	// Move to activation mark, nothing should change
	test.clock.Add(30 * time.Second)

	require.Equal(t, "jwt-a", test.fakeCAManager.currentJWTKeySlot.keyID)
	require.True(t, test.fakeCAManager.currentJWTKeySlot.isActive)
	require.Equal(t, "jwt-b", test.fakeCAManager.nextJWTKeySlot.keyID)
	require.False(t, test.fakeCAManager.nextJWTKeySlot.IsEmpty())

	// Move after activation mark, next move to current
	test.clock.Add(30 * time.Second)

	test.fakeCAManager.waitJWTKeyUpdate(ctx, t)

	require.Equal(t, "jwt-b", test.fakeCAManager.currentJWTKeySlot.keyID)
	require.True(t, test.fakeCAManager.currentJWTKeySlot.isActive)
	require.Equal(t, "jwt-a", test.fakeCAManager.nextJWTKeySlot.keyID)
	require.True(t, test.fakeCAManager.nextJWTKeySlot.IsEmpty())
}

func TestRunX509CARotation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	test := setupTest(t)

	go func() {
		err := test.rotator.Run(ctx)
		assert.NoError(t, err)
	}()

	require.Equal(t, "x509-a", test.fakeCAManager.currentX509CASlot.keyID)
	require.True(t, test.fakeCAManager.currentX509CASlot.isActive)
	// No next prepared
	require.True(t, test.fakeCAManager.nextX509CASlot.IsEmpty())

	// Move to preparation mark nothing should change
	test.clock.Add(time.Minute)

	require.Equal(t, "x509-a", test.fakeCAManager.currentX509CASlot.keyID)
	require.True(t, test.fakeCAManager.currentX509CASlot.isActive)
	require.Equal(t, "x509-b", test.fakeCAManager.nextX509CASlot.keyID)
	require.True(t, test.fakeCAManager.nextX509CASlot.IsEmpty())

	// Move after preparation mark
	test.clock.Add(30 * time.Second)

	test.fakeCAManager.waitX509CAUpdate(ctx, t)

	require.Equal(t, "x509-a", test.fakeCAManager.currentX509CASlot.keyID)
	require.True(t, test.fakeCAManager.currentX509CASlot.isActive)
	require.Equal(t, "x509-b", test.fakeCAManager.nextX509CASlot.keyID)
	require.False(t, test.fakeCAManager.nextX509CASlot.IsEmpty())

	// Move to activation mark, nothing should change
	test.clock.Add(30 * time.Second)

	require.Equal(t, "x509-a", test.fakeCAManager.currentX509CASlot.keyID)
	require.True(t, test.fakeCAManager.currentX509CASlot.isActive)
	require.Equal(t, "x509-b", test.fakeCAManager.nextX509CASlot.keyID)
	require.False(t, test.fakeCAManager.nextX509CASlot.IsEmpty())

	// Move after activation mark, next move to current
	test.clock.Add(30 * time.Second)

	test.fakeCAManager.waitX509CAUpdate(ctx, t)

	require.Equal(t, "x509-b", test.fakeCAManager.currentX509CASlot.keyID)
	require.True(t, test.fakeCAManager.currentX509CASlot.isActive)
	require.Equal(t, "x509-a", test.fakeCAManager.nextX509CASlot.keyID)
	require.True(t, test.fakeCAManager.nextX509CASlot.IsEmpty())
}

func TestPruneBundle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	test := setupTest(t)

	go func() {
		err := test.rotator.Run(ctx)
		assert.NoError(t, err)
	}()

	test.clock.Add(time.Minute + time.Second)
	require.False(t, test.fakeCAManager.pruneBundleWasCalled)

	currentJWTKey := test.fakeCAManager.GetCurrentJWTKeySlot()
	require.Equal(t, "jwt-a", currentJWTKey.KmKeyID())
	require.False(t, currentJWTKey.IsEmpty())

	nextJWTKey := test.fakeCAManager.GetNextJWTKeySlot()
	require.Equal(t, "jwt-b", nextJWTKey.KmKeyID())
	require.True(t, nextJWTKey.IsEmpty())

	currentX509CA := test.fakeCAManager.GetCurrentX509CASlot()
	require.Equal(t, "x509-a", currentX509CA.KmKeyID())
	require.False(t, currentX509CA.IsEmpty())

	nextX509CA := test.fakeCAManager.GetNextX509CASlot()
	require.Equal(t, "x509-b", nextX509CA.KmKeyID())
	require.True(t, nextX509CA.IsEmpty())

	// Prune bundle was called successfully
	test.clock.Add(pruneBundleInterval)
	test.fakeCAManager.waitPruneBundleCalled(ctx, t)

	require.True(t, test.fakeCAManager.pruneBundleWasCalled)
}

func TestPruneCAJournals(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	test := setupTest(t)

	go func() {
		err := test.rotator.Run(ctx)
		assert.NoError(t, err)
	}()
	test.clock.WaitForTicker(time.Minute, "waiting for the Run() ticker")

	test.clock.Add(time.Minute + time.Second)
	require.False(t, test.fakeCAManager.pruneCAJournalsWasCalled)

	// Prune CA journals was called successfully
	test.clock.Add(pruneCAJournalsInterval)
	test.fakeCAManager.waitPruneCAJournalsCalled(ctx, t)

	require.True(t, test.fakeCAManager.pruneCAJournalsWasCalled)
}

type rotationTest struct {
	rotator *Rotator

	clock         *clock.Mock
	logHook       *test.Hook
	fakeCAManager *fakeCAManager
	healthChecker *fakehealthchecker.Checker
}

func setupTest(tb testing.TB) *rotationTest {
	log, logHook := test.NewNullLogger()
	clock := clock.NewMock(tb)
	fManager := &fakeCAManager{
		clk: clock,

		x509CACh:          make(chan struct{}, 1),
		jwtKeyCh:          make(chan struct{}, 1),
		pruneBundleCh:     make(chan struct{}, 1),
		pruneCAJournalsCh: make(chan struct{}, 1),
	}
	fakeHealthChecker := fakehealthchecker.New()

	now := clock.Now()
	fManager.currentJWTKeySlot = createSlot("jwt-a", now, true)
	fManager.currentX509CASlot = createSlot("x509-a", now, true)
	fManager.nextJWTKeySlot = createSlot("jwt-b", now, false)
	fManager.nextX509CASlot = createSlot("x509-b", now, false)

	rotator := NewRotator(Config{
		Manager:       fManager,
		Log:           log,
		Clock:         clock,
		HealthChecker: fakeHealthChecker,
	})
	return &rotationTest{
		rotator: rotator,

		clock:         clock,
		logHook:       logHook,
		fakeCAManager: fManager,
		healthChecker: fakeHealthChecker,
	}
}

type fakeCAManager struct {
	clk clock.Clock

	notifyBundleLoadedErr error

	currentX509CASlot *fakeSlot
	nextX509CASlot    *fakeSlot
	prepareX509CAErr  error

	currentJWTKeySlot *fakeSlot
	nextJWTKeySlot    *fakeSlot
	prepareJWTKeyErr  error

	x509CACh chan struct{}
	jwtKeyCh chan struct{}

	pruneBundleWasCalled     bool
	pruneBundleCh            chan struct{}
	pruneCAJournalsCh        chan struct{}
	pruneCAJournalsWasCalled bool
}

func (f *fakeCAManager) NotifyBundleLoaded(context.Context) error {
	if f.notifyBundleLoadedErr != nil {
		return f.notifyBundleLoadedErr
	}
	return nil
}

func (f *fakeCAManager) ProcessBundleUpdates(context.Context) {
}

func (f *fakeCAManager) GetCurrentX509CASlot() manager.Slot {
	return f.currentX509CASlot
}

func (f *fakeCAManager) GetNextX509CASlot() manager.Slot {
	return f.nextX509CASlot
}

func (f *fakeCAManager) PrepareX509CA(context.Context) error {
	f.cleanX509CACh()

	if f.prepareX509CAErr != nil {
		return f.prepareX509CAErr
	}

	slot := f.nextX509CASlot
	if !f.currentX509CASlot.hasValue {
		slot = f.currentX509CASlot
	}

	slot.hasValue = true
	slot.preparationTime = f.clk.Now().Add(time.Minute)
	slot.activationTime = f.clk.Now().Add(2 * time.Minute)

	f.x509CACh <- struct{}{}

	return nil
}

func (f *fakeCAManager) ActivateX509CA(context.Context) {
	f.cleanX509CACh()
	f.currentX509CASlot.isActive = true
	f.x509CACh <- struct{}{}
}

func (f *fakeCAManager) RotateX509CA(context.Context) {
	f.cleanX509CACh()
	currentID := f.currentX509CASlot.keyID

	f.currentX509CASlot.keyID = f.nextX509CASlot.keyID
	f.currentX509CASlot.isActive = true
	f.nextX509CASlot.keyID = currentID
	f.nextX509CASlot.hasValue = false

	f.x509CACh <- struct{}{}
}

func (f *fakeCAManager) GetCurrentJWTKeySlot() manager.Slot {
	return f.currentJWTKeySlot
}

func (f *fakeCAManager) GetNextJWTKeySlot() manager.Slot {
	return f.nextJWTKeySlot
}

func (f *fakeCAManager) PrepareJWTKey(context.Context) error {
	f.cleanJWTKeyCh()
	if f.prepareJWTKeyErr != nil {
		return f.prepareJWTKeyErr
	}

	slot := f.nextJWTKeySlot
	if !f.currentJWTKeySlot.hasValue {
		slot = f.currentJWTKeySlot
	}

	slot.hasValue = true
	slot.preparationTime = f.clk.Now().Add(time.Minute)
	slot.activationTime = f.clk.Now().Add(2 * time.Minute)
	f.jwtKeyCh <- struct{}{}
	return nil
}

func (f *fakeCAManager) ActivateJWTKey(context.Context) {
	f.cleanJWTKeyCh()
	f.currentJWTKeySlot.isActive = true
	f.jwtKeyCh <- struct{}{}
}

func (f *fakeCAManager) RotateJWTKey(context.Context) {
	f.cleanJWTKeyCh()
	currentID := f.currentJWTKeySlot.keyID

	f.currentJWTKeySlot.keyID = f.nextJWTKeySlot.keyID
	f.currentJWTKeySlot.isActive = true
	f.nextJWTKeySlot.keyID = currentID
	f.nextJWTKeySlot.hasValue = false
	f.jwtKeyCh <- struct{}{}
}

func (f *fakeCAManager) SubscribeToLocalBundle(ctx context.Context) error {
	return nil
}

func (f *fakeCAManager) PruneBundle(context.Context) error {
	defer func() {
		f.pruneBundleCh <- struct{}{}
	}()
	f.pruneBundleWasCalled = true

	return nil
}

func (f *fakeCAManager) PruneCAJournals(context.Context) error {
	defer func() {
		f.pruneCAJournalsCh <- struct{}{}
	}()
	f.pruneCAJournalsWasCalled = true

	return nil
}

func (f *fakeCAManager) cleanX509CACh() {
	select {
	case <-f.x509CACh:
	default:
	}
}

func (f *fakeCAManager) cleanJWTKeyCh() {
	select {
	case <-f.jwtKeyCh:
	default:
	}
}

func (f *fakeCAManager) waitX509CAUpdate(ctx context.Context, t *testing.T) {
	select {
	case <-ctx.Done():
		assert.Fail(t, "context finished")
	case <-f.x509CACh:
	}
}

func (f *fakeCAManager) waitJWTKeyUpdate(ctx context.Context, t *testing.T) {
	select {
	case <-ctx.Done():
		assert.Fail(t, "context finished")
	case <-f.jwtKeyCh:
	}
}

func (f *fakeCAManager) waitPruneBundleCalled(ctx context.Context, t *testing.T) {
	select {
	case <-ctx.Done():
		assert.Fail(t, "context finished")
	case <-f.pruneBundleCh:
	}
}

func (f *fakeCAManager) waitPruneCAJournalsCalled(ctx context.Context, t *testing.T) {
	select {
	case <-ctx.Done():
		assert.Fail(t, "context finished")
	case <-f.pruneCAJournalsCh:
	}
}

type fakeSlot struct {
	manager.Slot

	keyID           string
	preparationTime time.Time
	activationTime  time.Time
	hasValue        bool
	isActive        bool
	status          journal.Status
}

func (s *fakeSlot) KmKeyID() string {
	return s.keyID
}

func (s *fakeSlot) IsEmpty() bool {
	return !s.hasValue || s.status == journal.Status_OLD
}

func (s *fakeSlot) Reset() {
	s.hasValue = false
	s.isActive = false
	s.status = journal.Status_OLD
}

func (s *fakeSlot) ShouldPrepareNext(now time.Time) bool {
	return !s.hasValue || now.After(s.preparationTime)
}

func (s *fakeSlot) ShouldActivateNext(now time.Time) bool {
	return !s.hasValue || now.After(s.activationTime)
}

func (s *fakeSlot) Status() journal.Status {
	return s.status
}

func createSlot(id string, now time.Time, hasValue bool) *fakeSlot {
	return &fakeSlot{
		keyID:           id,
		preparationTime: now.Add(time.Minute),
		activationTime:  now.Add(2 * time.Minute),
		hasValue:        hasValue,
		isActive:        hasValue,
	}
}
