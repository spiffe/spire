package agentstore

import (
	"context"
	"testing"

	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/server/datastore"
	"github.com/spiffe/spire/proto/spire/server/hostservices"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestAgentStore(t *testing.T) {
	ds := fakedatastore.New()
	_, err := ds.CreateAttestedNode(context.Background(), &datastore.CreateAttestedNodeRequest{
		Node: &common.AttestedNode{
			SpiffeId: "spiffe://domain.test/spire/agent/test/foo",
		},
	})
	require.NoError(t, err)

	deps := &Deps{
		DataStore: ds,
	}

	testCases := []struct {
		name    string
		deps    *Deps
		agentID string
		code    codes.Code
		depsErr string
		getErr  string
	}{
		{
			name:   "precondition failure when no deps set",
			code:   codes.FailedPrecondition,
			getErr: "AgentStore host service has not been initialized",
		},
		{
			name:    "deps missing datastore",
			deps:    &Deps{},
			depsErr: "required DataStore dependency is missing",
		},
		{
			name:    "no such agent",
			deps:    deps,
			agentID: "spiffe://domain.test/spire/agent/test/bar",
			code:    codes.NotFound,
			getErr:  "no such agent",
		},
		{
			name:    "success",
			agentID: "spiffe://domain.test/spire/agent/test/foo",
			deps:    deps,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			s := New()
			if testCase.deps != nil {
				err := s.SetDeps(*testCase.deps)
				if testCase.depsErr != "" {
					spiretest.AssertErrorContains(t, err, testCase.depsErr)
					return
				}
			}

			resp, err := s.GetAgentInfo(context.Background(), &hostservices.GetAgentInfoRequest{
				AgentId: testCase.agentID,
			})
			if testCase.getErr != "" {
				spiretest.AssertGRPCStatusContains(t, err, testCase.code, testCase.getErr)
				assert.Nil(resp)
				return
			}
			require.NoError(err)
			require.NotNil(t, resp)
			assert.Equal(resp.Info.AgentId, testCase.agentID)
		})
	}
}
