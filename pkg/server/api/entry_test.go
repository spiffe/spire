package api_test

import (
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

func TestRegistrationEntryToProto(t *testing.T) {
	expiresAt := time.Now().Unix()

	for _, tt := range []struct {
		name        string
		entry       *common.RegistrationEntry
		err         string
		expectEntry *types.Entry
	}{
		{
			name: "success",
			entry: &common.RegistrationEntry{
				EntryId:  "entry1",
				ParentId: "spiffe://example.org/foo",
				SpiffeId: "spiffe://example.org/bar",
				Ttl:      60,
				Selectors: []*common.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
				FederatesWith: []string{
					"spiffe://domain1.com",
					"spiffe://domain2.com",
				},
				Admin:       true,
				EntryExpiry: expiresAt,
				DnsNames:    []string{"dns1", "dns2"},
				Downstream:  true,
			},
			expectEntry: &types.Entry{
				Id:       "entry1",
				ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
				SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
				Ttl:      60,
				Selectors: []*types.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
				FederatesWith: []string{
					"spiffe://domain1.com",
					"spiffe://domain2.com",
				},
				Admin:      true,
				ExpiresAt:  expiresAt,
				DnsNames:   []string{"dns1", "dns2"},
				Downstream: true,
			},
		},
		{
			name: "missing entry",
			err:  "missing registration entry",
		},
		{
			name: "malformed ParentId",
			entry: &common.RegistrationEntry{
				ParentId: "malformed ParentID",
				SpiffeId: "spiffe://example.org/bar",
			},
			err: "spiffeid: invalid scheme",
		},
		{
			name: "malformed SpiffeId",
			entry: &common.RegistrationEntry{
				ParentId: "spiffe://example.org/foo",
				SpiffeId: "malformed SpiffeID",
			},
			err: "spiffeid: invalid scheme",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			entry, err := api.RegistrationEntryToProto(tt.entry)
			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				require.Nil(t, entry)

				return
			}

			require.NoError(t, err)
			spiretest.AssertProtoEqual(t, tt.expectEntry, entry)
		})
	}
}
