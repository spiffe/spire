package awsiid

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	testAccountListTTL = "1m"
)

func TestIsMemberAccount(t *testing.T) {
	testOrgValidationConfig := &orgValidationConfig{
		AccountID:      testAccountID,
		AccountRole:    testProfile,
		AccountRegion:  testRegion,
		AccountListTTL: testAccountListTTL,
	}
	testOrgValidator := newOrganizationValidationBase(testOrgValidationConfig)
	err := testOrgValidator.configure(testOrgValidationConfig)
	require.NoError(t, err)

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
	testOrgValidationConfig := &orgValidationConfig{
		AccountID:      testAccountID,
		AccountRole:    testProfile,
		AccountRegion:  testRegion,
		AccountListTTL: testAccountListTTL,
	}
	testOrgValidator := newOrganizationValidationBase(testOrgValidationConfig)
	err := testOrgValidator.configure(testOrgValidationConfig)
	require.NoError(t, err)

	testIsStale := testOrgValidator.checkIfOrgAccountListIsStale(context.Background())
	require.Equal(t, testIsStale, true)

	// seed account list and it should return false
	_, err = testOrgValidator.reloadAccountList(context.Background(), newFakeClient(), false)
	require.NoError(t, err)
	testIsStale = testOrgValidator.checkIfOrgAccountListIsStale(context.Background())
	require.Equal(t, testIsStale, false)
}

func TestReloadAccountList(t *testing.T) {
	testOrgValidationConfig := &orgValidationConfig{
		AccountID:      testAccountID,
		AccountRole:    testProfile,
		AccountRegion:  testRegion,
		AccountListTTL: testAccountListTTL,
	}
	testOrgValidator := newOrganizationValidationBase(testOrgValidationConfig)
	err := testOrgValidator.configure(testOrgValidationConfig)
	require.NoError(t, err)

	testClient := newFakeClient()

	// check once config is provided correctly and catchburst is false, account list popped up along with timestamp
	_, err = testOrgValidator.reloadAccountList(context.Background(), testClient, false)
	require.NoError(t, err)
	require.Equal(t, len(testOrgValidator.orgListAccountMap), 1)
	require.Greater(t, testOrgValidator.orgListAccountMapCreationTime, time.Now().Add(-10*time.Second))
	require.Equal(t, testOrgValidator.retries, orgAccountRetries)

	// do catchburst and confirm timestamp is not updated, but account list is popped up correctly
	existingTimeStamp := testOrgValidator.orgListAccountMapCreationTime
	// empty the account list before making call again
	testOrgValidator.orgListAccountMap = make(map[string]any)
	require.Equal(t, len(testOrgValidator.orgListAccountMap), 0)

	_, err = testOrgValidator.reloadAccountList(context.Background(), testClient, true)
	require.NoError(t, err)
	require.Equal(t, existingTimeStamp, testOrgValidator.orgListAccountMapCreationTime)
	require.Equal(t, len(testOrgValidator.orgListAccountMap), 1)
}

func TestCheckIfTTLIsExpired(t *testing.T) {
	testCurrentTime := time.Now()
	testCreationTime := testCurrentTime.Add(-2 * time.Minute)
	testTTL := time.Minute * 1

	// expect expired, creation time of 2 minutes back and ttl as 1 minute should return expire
	expired := checkIfTTLIsExpired(testCreationTime, testTTL)
	require.Equal(t, expired, true)

	// expect not expired, current time and ttl as 1 minute should return not expire
	expired = checkIfTTLIsExpired(testCurrentTime, testTTL)
	require.Equal(t, expired, false)
}
