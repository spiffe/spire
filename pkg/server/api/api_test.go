package api_test

import (
	"testing"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/require"
)

func TestNodeSelectorsToProto(t *testing.T) {
	testCases := []struct {
		name          string
		nodeSelectors *datastore.NodeSelectors
		selectors     []*types.Selector
		err           string
	}{
		{
			name: "success",
			nodeSelectors: &datastore.NodeSelectors{
				SpiffeID: "spiffe://example.org/agent",
				Selectors: []*common.Selector{
					{
						Type:  "type",
						Value: "value",
					},
				},
			},
			selectors: []*types.Selector{
				{
					Type:  "type",
					Value: "value",
				},
			},
		},
		{
			name: "missing node selectors",
			err:  "missing node selectors",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			selectors, err := api.NodeSelectorsToProto(testCase.nodeSelectors)
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}
			require.Equal(t, testCase.selectors, selectors)
		})
	}
}
