//go:build windows
// +build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"google.golang.org/grpc/codes"
)

var (
	ctx              = context.Background()
	sidUser, _       = windows.StringToSid("S-1-5-21-759542327-988462579-1707944338-1001")
	sidGroup1, _     = windows.StringToSid("S-1-5-21-759542327-988462579-1707944338-1004")
	sidGroup2, _     = windows.StringToSid("S-1-5-21-759542327-988462579-1707944338-1005")
	sidGroup3, _     = windows.StringToSid("S-1-2-0")
	sidAndAttrGroup1 = windows.SIDAndAttributes{
		Sid:        sidGroup1,
		Attributes: windows.SE_GROUP_ENABLED,
	}
	sidAndAttrGroup2 = windows.SIDAndAttributes{
		Sid:        sidGroup2,
		Attributes: windows.SE_GROUP_USE_FOR_DENY_ONLY,
	}
	sidAndAttrGroup3 = windows.SIDAndAttributes{
		Sid:        sidGroup3,
		Attributes: windows.SE_GROUP_ENABLED,
	}
)

func TestAttest(t *testing.T) {
	testCases := []struct {
		name           string
		selectorValues []string
		config         string
		pq             *fakeProcessQuery
		expectCode     codes.Code
		expectMsg      string
		expectLogs     []spiretest.LogEntry
	}{
		{
			name: "successful no groups",
			pq: &fakeProcessQuery{
				handle:      windows.InvalidHandle,
				tokenUser:   &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}},
				tokenGroups: &windows.Tokengroups{},
				account:     "user1",
				domain:      "domain1",
			},
			selectorValues: []string{
				"windows:user_name:domain1\\user1",
				"windows:user_sid:" + sidUser.String(),
			},
			expectCode: codes.OK,
		},
		{
			name: "successful with groups all enabled",
			pq: &fakeProcessQuery{
				handle:           windows.InvalidHandle,
				tokenUser:        &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}},
				tokenGroups:      &windows.Tokengroups{Groups: [1]windows.SIDAndAttributes{sidAndAttrGroup1}},
				account:          "user1",
				domain:           "domain1",
				sidAndAttributes: []windows.SIDAndAttributes{sidAndAttrGroup1, sidAndAttrGroup3},
			},
			selectorValues: []string{
				"windows:user_name:domain1\\user1",
				"windows:user_sid:" + sidUser.String(),
				"windows:group_sid:se_group_enabled:true:" + sidGroup1.String(),
				"windows:group_sid:se_group_enabled:true:" + sidGroup3.String(),
				"windows:group_name:se_group_enabled:true:domain1\\group1",
				"windows:group_name:se_group_enabled:true:LOCAL",
			},
			expectCode: codes.OK,
		},
		{
			name: "successful with not enabled group",
			pq: &fakeProcessQuery{
				handle:           windows.InvalidHandle,
				tokenUser:        &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}},
				tokenGroups:      &windows.Tokengroups{Groups: [1]windows.SIDAndAttributes{sidAndAttrGroup2}},
				account:          "user1",
				domain:           "domain",
				sidAndAttributes: []windows.SIDAndAttributes{sidAndAttrGroup2},
			},
			selectorValues: []string{
				"windows:user_name:domain1\\user1",
				"windows:user_sid:" + sidUser.String(),
				"windows:group_sid:se_group_enabled:false:" + sidGroup2.String(),
				"windows:group_name:se_group_enabled:false:domain2\\group2",
			},
			expectCode: codes.OK,
		},
		{
			name: "OpenProcess error",
			pq: &fakeProcessQuery{
				openProcessErr: errors.New("open process error"),
			},
			expectCode: codes.Internal,
			expectMsg:  "workloadattestor(windows): failed to get process information: failed to open process: open process error",
		},
		{
			name: "OpenProcessToken error",
			pq: &fakeProcessQuery{
				openProcessTokenErr: errors.New("open process token error"),
				handle:              windows.InvalidHandle,
			},
			expectCode: codes.Internal,
			expectMsg:  "workloadattestor(windows): failed to get process information: failed to open the access token associated with the process: open process token error",
		},
		{
			name: "GetTokenUser error",
			pq: &fakeProcessQuery{
				getTokenUserErr: errors.New("get token user error"),
				handle:          windows.InvalidHandle,
			},
			expectCode: codes.Internal,
			expectMsg:  "workloadattestor(windows): failed to get process information: failed to retrieve user account information from access token: get token user error",
		},
		{
			name: "GetTokenGroups error",
			pq: &fakeProcessQuery{
				getTokenGroupsErr: errors.New("get token groups error"),
				handle:            windows.InvalidHandle,
				tokenUser:         &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}},
			},
			expectCode: codes.Internal,
			expectMsg:  "workloadattestor(windows): failed to get process information: failed to retrieve group accounts information from access token: get token groups error",
		},
		{
			name: "LookupAccount failure",
			pq: &fakeProcessQuery{
				lookupAccountErr: errors.New("lookup error"),
				handle:           windows.InvalidHandle,
				tokenUser:        &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}},
				tokenGroups:      &windows.Tokengroups{Groups: [1]windows.SIDAndAttributes{sidAndAttrGroup1}},
				sidAndAttributes: []windows.SIDAndAttributes{sidAndAttrGroup1},
			},
			selectorValues: []string{
				"windows:user_sid:" + sidUser.String(),
				"windows:group_sid:se_group_enabled:true:" + sidGroup1.String(),
			},
			expectCode: codes.OK,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "failed to lookup account from user SID",
					Data: logrus.Fields{
						"sid":           sidUser.String(),
						logrus.ErrorKey: "lookup error",
					},
				},
				{
					Level:   logrus.WarnLevel,
					Message: "failed to lookup account from group SID",
					Data: logrus.Fields{
						"sid":           sidGroup1.String(),
						logrus.ErrorKey: "lookup error",
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			test := setupTest()
			p := test.loadPlugin(t, testCase.pq)

			selectors, err := p.Attest(ctx, 123)
			spiretest.RequireGRPCStatus(t, err, testCase.expectCode, testCase.expectMsg)
			if testCase.expectCode != codes.OK {
				require.Nil(t, selectors)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, selectors)
			var selectorValues []string
			for _, selector := range selectors {
				selectorValues = append(selectorValues, selector.Type+":"+selector.Value)
			}
			require.Equal(t, testCase.selectorValues, selectorValues)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), testCase.expectLogs)
		})
	}
}

type windowsTest struct {
	log     logrus.FieldLogger
	logHook *test.Hook
}

func (w *windowsTest) loadPlugin(t *testing.T, q *fakeProcessQuery) workloadattestor.WorkloadAttestor {
	p := New()
	p.q = q

	v1 := new(workloadattestor.V1)
	plugintest.Load(t, builtin(p), v1, plugintest.Log(w.log))
	return v1
}

type fakeProcessQuery struct {
	handle           windows.Handle
	tokenUser        *windows.Tokenuser
	tokenGroups      *windows.Tokengroups
	account, domain  string
	sidAndAttributes []windows.SIDAndAttributes

	openProcessErr      error
	openProcessTokenErr error
	lookupAccountErr    error
	getTokenUserErr     error
	getTokenGroupsErr   error
}

func (q *fakeProcessQuery) OpenProcess(pid int32) (handle windows.Handle, err error) {
	return q.handle, q.openProcessErr
}

func (q *fakeProcessQuery) OpenProcessToken(h windows.Handle, token *windows.Token) (err error) {
	return q.openProcessTokenErr
}

func (q *fakeProcessQuery) LookupAccount(sid *windows.SID) (account, domain string, err error) {
	if q.lookupAccountErr != nil {
		return "", "", q.lookupAccountErr
	}

	switch sid {
	case sidUser:
		return "user1", "domain1", nil
	case sidGroup1:
		return "group1", "domain1", nil
	case sidGroup2:
		return "group2", "domain2", nil
	case sidGroup3:
		return "LOCAL", "", nil
	}

	return "", "", fmt.Errorf("sid not expected: %s", sid.String())
}

func (q *fakeProcessQuery) GetTokenUser(t *windows.Token) (*windows.Tokenuser, error) {
	return q.tokenUser, q.getTokenUserErr
}

func (q *fakeProcessQuery) GetTokenGroups(t *windows.Token) (*windows.Tokengroups, error) {
	return q.tokenGroups, q.getTokenGroupsErr
}

func (q *fakeProcessQuery) AllGroups(t *windows.Tokengroups) []windows.SIDAndAttributes {
	return q.sidAndAttributes
}

func setupTest() *windowsTest {
	log, logHook := test.NewNullLogger()
	return &windowsTest{
		log:     log,
		logHook: logHook,
	}
}
