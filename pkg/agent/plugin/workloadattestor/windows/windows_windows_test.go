//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"google.golang.org/grpc/codes"
)

var (
	ctx              = context.Background()
	testPID          = 123
	sidUser, _       = windows.StringToSid("S-1-5-21-759542327-988462579-1707944338-1001")
	sidGroup1, _     = windows.StringToSid("S-1-5-21-759542327-988462579-1707944338-1004")
	sidGroup2, _     = windows.StringToSid("S-1-5-21-759542327-988462579-1707944338-1005")
	sidGroup3, _     = windows.StringToSid("S-1-2-0")
	sidSvcUser, _    = windows.StringToSid("S-1-5-80-1234567890-1234567890-1234567890-12")
	sidSvcGroup, _   = windows.StringToSid("S-1-5-80-1234567890-1234567890-1234567890-13")
	sidAllSvc, _     = windows.StringToSid("S-1-5-80-0")
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
	sidAndAttrGroup4 = windows.SIDAndAttributes{
		Sid:        sidSvcGroup,
		Attributes: windows.SE_GROUP_ENABLED,
	}
	sidAndAttrGroup5 = windows.SIDAndAttributes{
		Sid:        sidSvcGroup,
		Attributes: windows.SE_GROUP_USE_FOR_DENY_ONLY,
	}
	sidAndAttrGroup6 = windows.SIDAndAttributes{
		Sid:        sidAllSvc,
		Attributes: windows.SE_GROUP_ENABLED,
	}
	sidAndAttrGroup7 = windows.SIDAndAttributes{
		Sid:        sidAllSvc,
		Attributes: windows.SE_GROUP_USE_FOR_DENY_ONLY,
	}
)

func TestAttest(t *testing.T) {
	d := t.TempDir()
	exe := filepath.Join(d, "exe")
	require.NoError(t, os.WriteFile(exe, []byte("data"), 0600))

	testCases := []struct {
		name            string
		trustDomain     string
		expectSelectors []string
		config          string
		pq              *fakeProcessQuery
		serviceInfos    []serviceInfo
		serviceInfoErr  error
		expectCode      codes.Code
		expectMsg       string
		expectLogs      []spiretest.LogEntry
	}{
		{
			name:        "successful no groups",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				handle:      windows.InvalidHandle,
				tokenUser:   &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}},
				tokenGroups: &windows.Tokengroups{},
				account:     "user1",
				domain:      "domain1",
			},
			expectSelectors: []string{
				"windows:user_name:domain1\\user1",
				"windows:user_sid:" + sidUser.String(),
			},
			expectCode: codes.OK,
		},
		{
			name:        "successful with groups all enabled",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				handle:           windows.InvalidHandle,
				tokenUser:        &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}},
				tokenGroups:      &windows.Tokengroups{Groups: [1]windows.SIDAndAttributes{sidAndAttrGroup1}},
				account:          "user1",
				domain:           "domain1",
				sidAndAttributes: []windows.SIDAndAttributes{sidAndAttrGroup1, sidAndAttrGroup3},
			},
			expectSelectors: []string{
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
			name:        "successful with not enabled group",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				handle:           windows.InvalidHandle,
				tokenUser:        &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}},
				tokenGroups:      &windows.Tokengroups{Groups: [1]windows.SIDAndAttributes{sidAndAttrGroup2}},
				account:          "user1",
				domain:           "domain",
				sidAndAttributes: []windows.SIDAndAttributes{sidAndAttrGroup2},
			},
			expectSelectors: []string{
				"windows:user_name:domain1\\user1",
				"windows:user_sid:" + sidUser.String(),
				"windows:group_sid:se_group_enabled:false:" + sidGroup2.String(),
				"windows:group_name:se_group_enabled:false:domain2\\group2",
			},
			expectCode: codes.OK,
		},
		{
			name:        "successful with groups, group name selectors disabled",
			trustDomain: "example.org",
			config:      "disable_group_name_selectors = true",
			pq: &fakeProcessQuery{
				handle:           windows.InvalidHandle,
				tokenUser:        &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}},
				tokenGroups:      &windows.Tokengroups{Groups: [1]windows.SIDAndAttributes{sidAndAttrGroup1}},
				account:          "user1",
				domain:           "domain1",
				sidAndAttributes: []windows.SIDAndAttributes{sidAndAttrGroup1, sidAndAttrGroup3},
			},
			expectSelectors: []string{
				"windows:user_name:domain1\\user1",
				"windows:user_sid:" + sidUser.String(),
				"windows:group_sid:se_group_enabled:true:" + sidGroup1.String(),
				"windows:group_sid:se_group_enabled:true:" + sidGroup3.String(),
			},
			expectCode: codes.OK,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Group name selectors disabled; only group_sid selectors will be produced for groups",
				},
			},
		},
		{
			name:        "successful getting path and hashing process binary",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				handle:      windows.InvalidHandle,
				tokenUser:   &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}},
				tokenGroups: &windows.Tokengroups{},
				account:     "user1",
				domain:      "domain1",
				exe:         exe,
			},
			config: "discover_workload_path = true",
			expectSelectors: []string{
				"windows:user_name:domain1\\user1",
				"windows:user_sid:" + sidUser.String(),
				fmt.Sprintf("windows:path:%s", exe),
				"windows:sha256:3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7",
			},
			expectCode: codes.OK,
		},
		{
			name:        "successful getting path, disabled hashing process binary",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				handle:      windows.InvalidHandle,
				tokenUser:   &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}},
				tokenGroups: &windows.Tokengroups{},
				account:     "user1",
				domain:      "domain1",
				exe:         exe,
			},
			config: "discover_workload_path = true\nworkload_size_limit = -1",
			expectSelectors: []string{
				"windows:user_name:domain1\\user1",
				"windows:user_sid:" + sidUser.String(),
				fmt.Sprintf("windows:path:%s", exe),
			},
			expectCode: codes.OK,
		},
		{
			name:        "successful with service discovery enabled",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				handle:      windows.InvalidHandle,
				tokenUser:   &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}},
				tokenGroups: &windows.Tokengroups{},
				account:     "user1",
				domain:      "domain1",
			},
			config: "enable_service_discovery = true",
			serviceInfos: []serviceInfo{
				{
					ServiceName: "service1",
				},
				{
					ServiceName: "service2",
				},
			},
			expectSelectors: []string{
				"windows:user_name:domain1\\user1",
				"windows:user_sid:" + sidUser.String(),
				"windows:service_name:service1",
				"windows:service_name:service2",
			},
			expectCode: codes.OK,
		},
		{
			name:        "successful with service discovery error ignored",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				handle:      windows.InvalidHandle,
				tokenUser:   &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}},
				tokenGroups: &windows.Tokengroups{},
				account:     "user1",
				domain:      "domain1",
			},
			config:         "enable_service_discovery = true",
			serviceInfoErr: errors.New("service discovery error"),
			expectSelectors: []string{
				"windows:user_name:domain1\\user1",
				"windows:user_sid:" + sidUser.String(),
			},
			expectCode: codes.OK,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "Unable to discover services for process",
					Data: logrus.Fields{
						logrus.ErrorKey: "service discovery error",
						telemetry.PID:   fmt.Sprint(testPID),
					},
				},
			},
		},
		{
			name:        "failed to get binary path",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				handle:           windows.InvalidHandle,
				tokenUser:        &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}},
				tokenGroups:      &windows.Tokengroups{},
				account:          "user1",
				domain:           "domain1",
				getProcessExeErr: errors.New("get process exe error"),
			},
			config:     "discover_workload_path = true\nworkload_size_limit = -1",
			expectCode: codes.Internal,
			expectMsg:  "workloadattestor(windows): failed to get process information: error getting process exe: get process exe error",
		},
		{
			name:        "failed to hash binary",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				handle:      windows.InvalidHandle,
				tokenUser:   &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}},
				tokenGroups: &windows.Tokengroups{},
				account:     "user1",
				domain:      "domain1",
				exe:         "unreadable",
			},
			config:     "discover_workload_path = true",
			expectCode: codes.Internal,
			expectMsg:  "workloadattestor(windows): SHA256 digest: open unreadable: The system cannot find the file specified.",
		},
		{
			name:        "binary exceeds limit size",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				handle:      windows.InvalidHandle,
				tokenUser:   &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}},
				tokenGroups: &windows.Tokengroups{},
				account:     "user1",
				domain:      "domain1",
				exe:         exe,
			},
			config:     "discover_workload_path = true\nworkload_size_limit = 2",
			expectCode: codes.Internal,
			expectMsg:  fmt.Sprintf("workloadattestor(windows): SHA256 digest: workload %s exceeds size limit (4 > 2)", exe),
		},
		{
			name:        "OpenProcess error",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				openProcessErr: errors.New("open process error"),
			},
			expectCode: codes.Internal,
			expectMsg:  "workloadattestor(windows): failed to get process information: failed to open process: open process error",
		},
		{
			name:        "OpenProcessToken error",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				openProcessTokenErr: errors.New("open process token error"),
				handle:              windows.InvalidHandle,
			},
			expectCode: codes.Internal,
			expectMsg:  "workloadattestor(windows): failed to get process information: failed to open the access token associated with the process: open process token error",
		},
		{
			name:        "GetTokenUser error",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				getTokenUserErr: errors.New("get token user error"),
				handle:          windows.InvalidHandle,
			},
			expectCode: codes.Internal,
			expectMsg:  "workloadattestor(windows): failed to get process information: failed to retrieve user account information from access token: get token user error",
		},
		{
			name:        "GetTokenGroups error",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				getTokenGroupsErr: errors.New("get token groups error"),
				handle:            windows.InvalidHandle,
				tokenUser:         &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}},
			},
			expectCode: codes.Internal,
			expectMsg:  "workloadattestor(windows): failed to get process information: failed to retrieve group accounts information from access token: get token groups error",
		},
		{
			name:        "LookupAccount failure",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				lookupAccountErr: errors.New("lookup error"),
				handle:           windows.InvalidHandle,
				tokenUser:        &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}},
				tokenGroups:      &windows.Tokengroups{Groups: [1]windows.SIDAndAttributes{sidAndAttrGroup1}},
				sidAndAttributes: []windows.SIDAndAttributes{sidAndAttrGroup1},
			},
			expectSelectors: []string{
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
						telemetry.PID:   fmt.Sprint(testPID),
					},
				},
				{
					Level:   logrus.WarnLevel,
					Message: "failed to lookup account from group SID",
					Data: logrus.Fields{
						"sid":           sidGroup1.String(),
						logrus.ErrorKey: "lookup error",
						telemetry.PID:   fmt.Sprint(testPID),
					},
				},
			},
		},
		{
			name:        "close handle error",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				handle:         windows.InvalidHandle,
				tokenUser:      &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}},
				tokenGroups:    &windows.Tokengroups{},
				account:        "user1",
				domain:         "domain1",
				closeHandleErr: errors.New("close handle error"),
			},
			expectSelectors: []string{
				"windows:user_name:domain1\\user1",
				"windows:user_sid:" + sidUser.String(),
			},
			expectCode: codes.OK,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "Could not close process handle",
					Data: logrus.Fields{
						logrus.ErrorKey: "close handle error",
						telemetry.PID:   fmt.Sprint(testPID),
					},
				},
			},
		},
		{
			name:        "close process token error",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				handle:               windows.InvalidHandle,
				tokenUser:            &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}},
				tokenGroups:          &windows.Tokengroups{},
				account:              "user1",
				domain:               "domain1",
				closeProcessTokenErr: errors.New("close process token error"),
			},
			expectSelectors: []string{
				"windows:user_name:domain1\\user1",
				"windows:user_sid:" + sidUser.String(),
			},
			expectCode: codes.OK,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "Could not close access token",
					Data: logrus.Fields{
						logrus.ErrorKey: "close process token error",
						telemetry.PID:   fmt.Sprint(testPID),
					},
				},
			},
		},
		{
			name:        "successful for service with groups enabled",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				handle:             windows.InvalidHandle,
				tokenUser:          &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidSvcUser}},
				tokenGroups:        &windows.Tokengroups{Groups: [1]windows.SIDAndAttributes{sidAndAttrGroup4}},
				account:            "NetworkService",
				domain:             "NT AUTHORITY",
				sidAndAttributes:   []windows.SIDAndAttributes{sidAndAttrGroup4},
				serviceDisplayName: "My Fancy Service Name",
			},
			expectSelectors: []string{
				"windows:user_name:NT AUTHORITY\\NetworkService",
				"windows:user_sid:" + sidSvcUser.String(),
				"windows:group_sid:se_group_enabled:true:" + sidSvcGroup.String(),
				"windows:group_name:se_group_enabled:true:My Service",
				"windows:service_name:My Service",
			},
			expectCode: codes.OK,
		},
		{
			name:        "successful for service with groups and discovery enabled without duplicates",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				handle:             windows.InvalidHandle,
				tokenUser:          &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidSvcUser}},
				tokenGroups:        &windows.Tokengroups{Groups: [1]windows.SIDAndAttributes{sidAndAttrGroup4}},
				account:            "NetworkService",
				domain:             "NT AUTHORITY",
				sidAndAttributes:   []windows.SIDAndAttributes{sidAndAttrGroup4},
				serviceDisplayName: "My Fancy Service Name",
			},
			config: "enable_service_discovery = true",
			serviceInfos: []serviceInfo{
				{
					ServiceName: "My Service",
				},
			},
			expectSelectors: []string{
				"windows:user_name:NT AUTHORITY\\NetworkService",
				"windows:user_sid:" + sidSvcUser.String(),
				"windows:group_sid:se_group_enabled:true:" + sidSvcGroup.String(),
				"windows:group_name:se_group_enabled:true:My Service",
				"windows:service_name:My Service",
			},
			expectCode: codes.OK,
		},
		{
			name:        "successful for service with groups disabled",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				handle:             windows.InvalidHandle,
				tokenUser:          &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidSvcUser}},
				tokenGroups:        &windows.Tokengroups{Groups: [1]windows.SIDAndAttributes{sidAndAttrGroup5}},
				account:            "NetworkService",
				domain:             "NT AUTHORITY",
				sidAndAttributes:   []windows.SIDAndAttributes{sidAndAttrGroup5},
				serviceDisplayName: "My Fancy Service Name",
			},
			expectSelectors: []string{
				"windows:user_name:NT AUTHORITY\\NetworkService",
				"windows:user_sid:" + sidSvcUser.String(),
				"windows:group_sid:se_group_enabled:false:" + sidSvcGroup.String(),
				"windows:group_name:se_group_enabled:false:My Service",
			},
			expectCode: codes.OK,
		},
		{
			name:        "successful for all service group",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				handle:           windows.InvalidHandle,
				tokenUser:        &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidAllSvc}},
				tokenGroups:      &windows.Tokengroups{Groups: [1]windows.SIDAndAttributes{sidAndAttrGroup6}},
				account:          "SYSTEM",
				domain:           "NT AUTHORITY",
				sidAndAttributes: []windows.SIDAndAttributes{sidAndAttrGroup6},
			},
			expectSelectors: []string{
				"windows:user_name:NT AUTHORITY\\SYSTEM",
				"windows:user_sid:" + sidAllSvc.String(),
				"windows:group_sid:se_group_enabled:true:" + sidAllSvc.String(),
				"windows:group_name:se_group_enabled:true:NT AUTHORITY\\SYSTEM",
			},
			expectCode: codes.OK,
		},
		{
			name:        "successful for all service with groups disabled",
			trustDomain: "example.org",
			pq: &fakeProcessQuery{
				handle:           windows.InvalidHandle,
				tokenUser:        &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidAllSvc}},
				tokenGroups:      &windows.Tokengroups{Groups: [1]windows.SIDAndAttributes{sidAndAttrGroup7}},
				account:          "SYSTEM",
				domain:           "NT AUTHORITY",
				sidAndAttributes: []windows.SIDAndAttributes{sidAndAttrGroup7},
			},
			expectSelectors: []string{
				"windows:user_name:NT AUTHORITY\\SYSTEM",
				"windows:user_sid:" + sidAllSvc.String(),
				"windows:group_sid:se_group_enabled:false:" + sidAllSvc.String(),
				"windows:group_name:se_group_enabled:false:NT AUTHORITY\\SYSTEM",
			},
			expectCode: codes.OK,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			test := setupTest()
			p, err := test.loadPlugin(t, testCase.pq, testCase.serviceInfos, testCase.serviceInfoErr, testCase.trustDomain, testCase.config)
			require.NoError(t, err)

			selectors, err := p.Attest(ctx, testPID)
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
			require.Equal(t, testCase.expectSelectors, selectorValues)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), testCase.expectLogs)
		})
	}
}

func TestConfigure(t *testing.T) {
	test := setupTest()

	// malformed configuration
	_, err := test.loadPlugin(t, &fakeProcessQuery{}, nil, nil, "example.org", "malformed")
	spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "failed to decode configuration")

	// success
	_, err = test.loadPlugin(t, &fakeProcessQuery{}, nil, nil, "example.org", "discover_workload_path = true\nworkload_size_limit = 2\nenable_service_discovery = true")
	require.NoError(t, err)
}

func TestServiceGetSCMRegisteredPid(t *testing.T) {
	testCases := []struct {
		name               string
		pid                uint32
		pq                 *fakeProcessQuery
		expectPID          uint32
		expectIsService    bool
		expectHandle       windows.Handle
		expectMsg          string
		expectParentPIDs   []uint32
		expectOpenedPIDs   []int32
		expectTokenHandles []windows.Handle
	}{
		{
			name:             "direct service does not query token",
			pid:              101,
			pq:               &fakeProcessQuery{openProcessErr: errors.New("unexpected process query")},
			expectPID:        101,
			expectIsService:  true,
			expectHandle:     0,
			expectParentPIDs: []uint32{100},
		},
		{
			name:               "child process with matching token user",
			pid:                102,
			pq:                 &fakeProcessQuery{handle: 1234, tokenUser: &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}}},
			expectPID:          101,
			expectIsService:    true,
			expectHandle:       1234,
			expectParentPIDs:   []uint32{101, 100},
			expectOpenedPIDs:   []int32{101},
			expectTokenHandles: []windows.Handle{1234},
		},
		{
			name:               "grandchild process with matching token user",
			pid:                103,
			pq:                 &fakeProcessQuery{handle: 1234, tokenUser: &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidUser}}},
			expectPID:          101,
			expectIsService:    true,
			expectHandle:       1234,
			expectParentPIDs:   []uint32{102, 101, 100},
			expectOpenedPIDs:   []int32{101},
			expectTokenHandles: []windows.Handle{1234},
		},
		{
			name:               "ancestor token user does not match",
			pid:                103,
			pq:                 &fakeProcessQuery{handle: 1234, tokenUser: &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: sidSvcUser}}},
			expectParentPIDs:   []uint32{102, 101, 100},
			expectOpenedPIDs:   []int32{101},
			expectHandle:       1234,
			expectTokenHandles: []windows.Handle{1234},
		},
		{
			name:             "open ancestor process error",
			pid:              102,
			pq:               &fakeProcessQuery{openProcessErr: errors.New("open process error")},
			expectMsg:        "open process error",
			expectParentPIDs: []uint32{101, 100},
			expectOpenedPIDs: []int32{101},
		},
		{
			name:               "open ancestor process token error",
			pid:                102,
			pq:                 &fakeProcessQuery{handle: 1234, openProcessTokenErr: errors.New("open token error")},
			expectMsg:          "failed to open the access token associated with the parent process: open token error",
			expectParentPIDs:   []uint32{101, 100},
			expectOpenedPIDs:   []int32{101},
			expectHandle:       1234,
			expectTokenHandles: []windows.Handle{1234},
		},
		{
			name:               "get ancestor token user error",
			pid:                102,
			pq:                 &fakeProcessQuery{handle: 1234, getTokenUserErr: errors.New("get token user error")},
			expectMsg:          "failed to retrieve user account information from access token: get token user error",
			expectParentPIDs:   []uint32{101, 100},
			expectOpenedPIDs:   []int32{101},
			expectHandle:       1234,
			expectTokenHandles: []windows.Handle{1234},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			oldSnapshotProcessesFunc := snapshotProcessesFunc
			oldProcessCreationTimeFunc := processCreationTimeFunc
			oldIsProcessSystemServicesRootFunc := isProcessSystemServicesRootFunc
			t.Cleanup(func() {
				snapshotProcessesFunc = oldSnapshotProcessesFunc
				processCreationTimeFunc = oldProcessCreationTimeFunc
				isProcessSystemServicesRootFunc = oldIsProcessSystemServicesRootFunc
			})

			snapshotProcessesFunc = func() (map[uint32]processSnapshotEntry, error) {
				return map[uint32]processSnapshotEntry{
					103: {parentPID: 102, exe: "grandchild.exe"},
					102: {parentPID: 101, exe: "child.exe"},
					101: {parentPID: 100, exe: "workload.exe"},
					100: {parentPID: 50, exe: "services.exe"},
					50:  {parentPID: 0, exe: "system.exe"},
				}, nil
			}
			processCreationTimeFunc = func(pid uint32) (uint64, error) {
				return uint64(pid), nil
			}
			var parentPIDs []uint32
			isProcessSystemServicesRootFunc = func(s *windowsService, pid uint32, process processSnapshotEntry) (bool, error) {
				parentPIDs = append(parentPIDs, pid)
				if pid == 100 {
					require.Equal(t, "services.exe", process.exe)
					return true, nil
				}
				return false, nil
			}

			service := &windowsService{servicesExePath: `C:\Windows\System32\services.exe`}
			pid, isService, handle, err := service.serviceGetSCMRegisteredPid(testCase.pid, sidUser.String(), testCase.pq)
			if testCase.expectMsg != "" {
				require.EqualError(t, err, testCase.expectMsg)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, testCase.expectPID, pid)
			require.Equal(t, testCase.expectIsService, isService)
			require.Equal(t, testCase.expectHandle, handle)
			require.Equal(t, testCase.expectParentPIDs, parentPIDs)
			require.Equal(t, testCase.expectOpenedPIDs, testCase.pq.openedProcessIDs)
			require.Equal(t, testCase.expectTokenHandles, testCase.pq.openedProcessTokenHandles)
		})
	}
}

type windowsTest struct {
	log     logrus.FieldLogger
	logHook *test.Hook
}

func (w *windowsTest) loadPlugin(t *testing.T, q *fakeProcessQuery, serviceInfos []serviceInfo, serviceInfoErr error, trustDomain string, config string) (workloadattestor.WorkloadAttestor, error) {
	var err error
	p := New()
	p.q = q
	p.findServicesForProcessFn = func(int32, string, processQueryer) ([]serviceInfo, error) {
		return serviceInfos, serviceInfoErr
	}

	v1 := new(workloadattestor.V1)
	plugintest.Load(t, builtin(p), v1,
		plugintest.Log(w.log),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString(trustDomain),
		}),
		plugintest.Configure(config),
		plugintest.CaptureConfigureError(&err))
	return v1, err
}

type fakeProcessQuery struct {
	handle             windows.Handle
	tokenUser          *windows.Tokenuser
	tokenGroups        *windows.Tokengroups
	account, domain    string
	sidAndAttributes   []windows.SIDAndAttributes
	exe                string
	serviceDisplayName string

	openProcessErr            error
	openProcessTokenErr       error
	lookupAccountErr          error
	getTokenUserErr           error
	getTokenGroupsErr         error
	closeHandleErr            error
	closeProcessTokenErr      error
	getProcessExeErr          error
	openedProcessIDs          []int32
	openedProcessTokenHandles []windows.Handle
}

func (q *fakeProcessQuery) OpenProcess(pid int32) (handle windows.Handle, err error) {
	q.openedProcessIDs = append(q.openedProcessIDs, pid)
	return q.handle, q.openProcessErr
}

func (q *fakeProcessQuery) OpenProcessToken(handle windows.Handle, _ *windows.Token) (err error) {
	q.openedProcessTokenHandles = append(q.openedProcessTokenHandles, handle)
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
	case sidSvcUser:
		return "NetworkService", "NT AUTHORITY", nil
	case sidSvcGroup:
		return "My Service", "", nil
	case sidAllSvc:
		return "SYSTEM", "NT AUTHORITY", nil
	}

	return "", "", fmt.Errorf("sid not expected: %s", sid.String())
}

func (q *fakeProcessQuery) GetTokenUser(*windows.Token) (*windows.Tokenuser, error) {
	return q.tokenUser, q.getTokenUserErr
}

func (q *fakeProcessQuery) GetTokenGroups(*windows.Token) (*windows.Tokengroups, error) {
	return q.tokenGroups, q.getTokenGroupsErr
}

func (q *fakeProcessQuery) AllGroups(*windows.Tokengroups) []windows.SIDAndAttributes {
	return q.sidAndAttributes
}

func (q *fakeProcessQuery) CloseHandle(windows.Handle) error {
	return q.closeHandleErr
}

func (q *fakeProcessQuery) CloseProcessToken(windows.Token) error {
	return q.closeProcessTokenErr
}

func (q *fakeProcessQuery) GetProcessExe(windows.Handle) (string, error) {
	return q.exe, q.getProcessExeErr
}

func setupTest() *windowsTest {
	log, logHook := test.NewNullLogger()
	return &windowsTest{
		log:     log,
		logHook: logHook,
	}
}
