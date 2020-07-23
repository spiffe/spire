package api_test

import (
	"testing"

	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

func TestProtoFromAttestedNode(t *testing.T) {
	for _, tt := range []struct {
		name        string
		n           *common.AttestedNode
		expectAgent *types.Agent
		expectErr   string
	}{
		{
			name: "success",
			n: &common.AttestedNode{
				SpiffeId:            "spiffe://example.org/node",
				AttestationDataType: "type",
				CertNotAfter:        1234,
				CertSerialNumber:    "serial1",
				NewCertNotAfter:     5678,
				NewCertSerialNumber: "serial2",
				Selectors: []*common.Selector{
					{Type: "t1", Value: "v1"},
					{Type: "t2", Value: "v2"},
					{Type: "t3", Value: "v3"},
				},
			},
			expectAgent: &types.Agent{
				Id:              &types.SPIFFEID{TrustDomain: "example.org", Path: "/node"},
				AttestationType: "type",
				Banned:          false,
				Selectors: []*types.Selector{
					{Type: "t1", Value: "v1"},
					{Type: "t2", Value: "v2"},
					{Type: "t3", Value: "v3"},
				},
				X509SvidExpiresAt:    1234,
				X509SvidSerialNumber: "serial1",
			},
		},
		{
			name: "banned",
			n: &common.AttestedNode{
				SpiffeId: "spiffe://example.org/node",
			},
			expectAgent: &types.Agent{
				Id:     &types.SPIFFEID{TrustDomain: "example.org", Path: "/node"},
				Banned: true,
			},
		},
		{
			name:      "missing attested node",
			expectErr: "missing attested node",
		},
		{
			name: "malformed SPIFFE ID",
			n: &common.AttestedNode{
				SpiffeId: "http://example.org/node",
			},
			expectErr: "spiffeid: invalid scheme",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			a, err := api.ProtoFromAttestedNode(tt.n)

			if tt.expectErr != "" {
				require.EqualError(t, err, tt.expectErr)
				require.Nil(t, a)
				return
			}

			require.Nil(t, err)
			spiretest.RequireProtoEqual(t, tt.expectAgent, a)
		})
	}
}
