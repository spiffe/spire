package awsiid

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/stretchr/testify/require"
)

const (
	testAccountListTTL = "1m"
	testClockMutAfter  = "after"
	testClockMutBefore = "before"

	testFileAccountID      = "111111111111"
	testFileAccountIDOther = "222222222222"
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

	// set retry to 0 and make sure the list is not updated
	testOrgValidator.retries = 0
	testOrgValidator.orgAccountList = make(map[string]any)
	_, err = testOrgValidator.reloadAccountList(context.Background(), testClient, true)
	require.NoError(t, err)
	require.Empty(t, testOrgValidator.orgAccountList)

	// make sure retry is reset, once we are over TTL
	// move clock ahead by 10 minutes. And as our TTL is 1 minute, it should refresh
	// the list
	testOrgValidator = buildOrgValidationClient()
	_, err = testOrgValidator.reloadAccountList(context.Background(), testClient, false)
	require.NoError(t, err)
	require.Len(t, testOrgValidator.orgAccountList, 1)
	testOrgValidator.clk = buildNewMockClock(10*time.Minute, testClockMutAfter)
	testOrgValidator.retries = 0 // trigger refresh to reset retries
	require.Equal(t, testOrgValidator.retries, 0)
	_, err = testOrgValidator.reloadAccountList(context.Background(), testClient, false)
	require.NoError(t, err)
	require.Equal(t, testOrgValidator.retries, orgAccountRetries)

	// make sure errors is handled when list accounts call fails
	// while making subsequent calls
	testOrgValidator = buildOrgValidationClient()
	testToken := "uncooolrandomtoken"
	testClient.ListAccountOutput = &organizations.ListAccountsOutput{
		Accounts: []types.Account{{
			Id:     &testAccountID,
			Status: types.AccountStatusActive,
		}},
		NextToken: &testToken,
	}
	_, err = testOrgValidator.reloadAccountList(context.Background(), testClient, false)
	require.ErrorContains(t, err, "issue while getting list of accounts")
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

func buildOrgValidationClientFromFile(path string) *orgValidator {
	testOrgValidationConfig := &orgValidationConfig{
		AccountListFile: path,
		AccountListTTL:  testAccountListTTL,
	}
	testOrgValidator := newOrganizationValidationBase(testOrgValidationConfig)
	_ = testOrgValidator.configure(testOrgValidationConfig)
	return testOrgValidator
}

// writeAccountListFile writes content to a temp file and returns its path.
func writeAccountListFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "org-accounts.json")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestParseAccountListFile(t *testing.T) {
	// valid file
	path := writeAccountListFile(t, `["111111111111", "222222222222"]`)
	accounts, err := parseAccountListFile(path)
	require.NoError(t, err)
	require.Len(t, accounts, 2)
	require.Contains(t, accounts, testFileAccountID)
	require.Contains(t, accounts, testFileAccountIDOther)

	// missing file
	_, err = parseAccountListFile(filepath.Join(t.TempDir(), "does-not-exist.json"))
	require.ErrorContains(t, err, "unable to read account list file")

	// malformed JSON
	path = writeAccountListFile(t, `{"not": "an array"}`)
	_, err = parseAccountListFile(path)
	require.ErrorContains(t, err, "unable to parse account list file")

	// invalid account id (not 12 digits)
	path = writeAccountListFile(t, `["123"]`)
	_, err = parseAccountListFile(path)
	require.ErrorContains(t, err, "invalid account id")

	// invalid account id (non-numeric)
	path = writeAccountListFile(t, `["abcdefghijkl"]`)
	_, err = parseAccountListFile(path)
	require.ErrorContains(t, err, "invalid account id")

	// empty array is valid
	path = writeAccountListFile(t, `[]`)
	accounts, err = parseAccountListFile(path)
	require.NoError(t, err)
	require.Empty(t, accounts)
}

func TestReloadAccountListFromFile(t *testing.T) {
	path := writeAccountListFile(t, `["111111111111", "222222222222"]`)
	testOrgValidator := buildOrgValidationClientFromFile(path)

	// account list is sourced from the file; no AWS client is needed (nil)
	_, err := testOrgValidator.reloadAccountList(context.Background(), nil, false)
	require.NoError(t, err)
	require.Len(t, testOrgValidator.orgAccountList, 2)
	require.Greater(t, testOrgValidator.orgAccountListValidDuration, time.Now())
	require.Equal(t, testOrgValidator.retries, orgAccountRetries)

	// a malformed file surfaces an error on reload once the cache is stale
	require.NoError(t, os.WriteFile(path, []byte(`not json`), 0o600))
	testOrgValidator.clk = buildNewMockClock(2*time.Minute, testClockMutAfter)
	_, err = testOrgValidator.reloadAccountList(context.Background(), nil, false)
	require.ErrorContains(t, err, "issue while reading org account list file")
}

func TestIsMemberAccountFromFile(t *testing.T) {
	path := writeAccountListFile(t, `["111111111111", "222222222222"]`)
	testOrgValidator := buildOrgValidationClientFromFile(path)

	// member account passes
	ok, err := testOrgValidator.IsMemberAccount(context.Background(), nil, testFileAccountID)
	require.NoError(t, err)
	require.True(t, ok)

	// non-member account fails
	ok, err = testOrgValidator.IsMemberAccount(context.Background(), nil, "999999999999")
	require.NoError(t, err)
	require.False(t, ok)
}

func TestReloadAccountListFromFileTTL(t *testing.T) {
	path := writeAccountListFile(t, `["111111111111"]`)
	testOrgValidator := buildOrgValidationClientFromFile(path)

	_, err := testOrgValidator.reloadAccountList(context.Background(), nil, false)
	require.NoError(t, err)
	require.Len(t, testOrgValidator.orgAccountList, 1)
	require.Contains(t, testOrgValidator.orgAccountList, testFileAccountID)

	// rewrite the file with a new account, then advance the clock past the TTL
	require.NoError(t, os.WriteFile(path, []byte(`["222222222222"]`), 0o600))
	testOrgValidator.clk = buildNewMockClock(10*time.Minute, testClockMutAfter)

	_, err = testOrgValidator.reloadAccountList(context.Background(), nil, false)
	require.NoError(t, err)
	require.Len(t, testOrgValidator.orgAccountList, 1)
	require.Contains(t, testOrgValidator.orgAccountList, testFileAccountIDOther)
	require.NotContains(t, testOrgValidator.orgAccountList, testFileAccountID)
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
