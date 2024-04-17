package awsiid

import (
	"context"
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/stretchr/testify/require"
)

const (
	testAccountListTTL = "1m"
	testClockMutAfter  = "after"
	testClockMutBefore = "before"
)

func TestIsMemberAccount(t *testing.T) {
	testOrgValidator := buildOrgValidationClient()
	testClient := newFakeClient()

	// pass valid account
	ok, err := testOrgValidator.IsMemberAccount(context.Background(), testClient, testAccountID)
	require.NoError(t, err)
	require.Equal(t, ok, true)

	// fail valid account doesnt exist
	ok, err = testOrgValidator.IsMemberAccount(context.Background(), testClient, "9999999")
	require.NoError(t, err)
	require.Equal(t, ok, false)
}

func TestCheckIfOrgAccountListIsStale(t *testing.T) {
	testOrgValidator := buildOrgValidationClient()

	testIsStale := testOrgValidator.checkIfOrgAccountListIsStale()
	require.True(t, testIsStale)

	// seed account list and it should return false
	_, err := testOrgValidator.reloadAccountList(context.Background(), newFakeClient(), false)
	require.NoError(t, err)
	testIsStale = testOrgValidator.checkIfOrgAccountListIsStale()
	require.False(t, testIsStale)
}

func TestReloadAccountList(t *testing.T) {
	testOrgValidator := buildOrgValidationClient()
	testClient := newFakeClient()

	// check once config is provided correctly and catchburst is false, account list popped up along with timestamp
	_, err := testOrgValidator.reloadAccountList(context.Background(), testClient, false)
	require.NoError(t, err)
	require.Len(t, testOrgValidator.orgAccountList, 1)
	require.Greater(t, testOrgValidator.orgAccountListValidDuration, time.Now())
	require.Equal(t, testOrgValidator.retries, orgAccountRetries)

	// check if the list of accounts is updated when catchburst is true
	// but the timestamp is not updated
	existingValidDuration := testOrgValidator.orgAccountListValidDuration
	testOrgValidator.orgAccountList = make(map[string]any)

	_, err = testOrgValidator.reloadAccountList(context.Background(), testClient, true)
	require.NoError(t, err)
	require.Equal(t, existingValidDuration, testOrgValidator.orgAccountListValidDuration)
	require.Len(t, testOrgValidator.orgAccountList, 1)
}

func TestCheckIfTTLIsExpired(t *testing.T) {
	testOrgValidator := buildOrgValidationClient()

	// expect not expired, move clock back by 10 minutes
	testOrgValidator.clk = buildNewMockClock(10*time.Minute, testClockMutBefore)
	expired := testOrgValidator.checkIfTTLIsExpired(time.Now())
	require.False(t, expired)

	// expect expired, move clock forward by 10 minute
	testOrgValidator.clk = buildNewMockClock(10*time.Minute, testClockMutAfter)
	expired = testOrgValidator.checkIfTTLIsExpired(time.Now())
	require.True(t, expired)
}

func buildOrgValidationClient() *orgValidator {
	testOrgValidationConfig := &orgValidationConfig{
		AccountID:      testAccountID,
		AccountRole:    testProfile,
		AccountRegion:  testRegion,
		AccountListTTL: testAccountListTTL,
	}
	testOrgValidator := newOrganizationValidationBase(testOrgValidationConfig)
	_ = testOrgValidator.configure(testOrgValidationConfig)
	return testOrgValidator
}

func buildNewMockClock(t time.Duration, mut string) *clock.Mock {
	testClock := clock.NewMock()
	switch mut := mut; mut {
	case testClockMutAfter:
		testClock.Set(time.Now().UTC())
		testClock.Add(t)
	case testClockMutBefore:
		testClock.Set(time.Now().UTC().Add(-t))
	}
	return testClock
}
