package api_test

import (
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/protoutil"
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
func TestProtoToRegistrationEntryWithMask(t *testing.T) {
	expiresAt := time.Now().Unix()

	for _, tt := range []struct {
		name        string
		entry       *types.Entry
		err         string
		expectEntry *common.RegistrationEntry
		mask        *types.EntryMask
	}{
		{
			name: "success",
			entry: &types.Entry{
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
					"domain2.com",
				},
				Admin:      true,
				ExpiresAt:  expiresAt,
				DnsNames:   []string{"dns1", "dns2"},
				Downstream: true,
			},
			expectEntry: &common.RegistrationEntry{
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
			mask: protoutil.AllTrueEntryMask,
		},
		{
			name: "success empty spiffe id",
			entry: &types.Entry{
				Id:       "entry1",
				ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
				Selectors: []*types.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
			},
			expectEntry: &common.RegistrationEntry{
				EntryId:  "entry1",
				ParentId: "spiffe://example.org/foo",
				SpiffeId: "",
				Selectors: []*common.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
			},
			mask: &types.EntryMask{
				SpiffeId:  false,
				ParentId:  true,
				Selectors: true,
			},
		},
		{
			name: "success empty selectors, ignore spiffe id field",
			entry: &types.Entry{
				Id:        "entry1",
				ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
				Selectors: []*types.Selector{},
			},
			expectEntry: &common.RegistrationEntry{
				EntryId:   "entry1",
				ParentId:  "spiffe://example.org/foo",
				Selectors: []*common.Selector{},
			},
			mask: &types.EntryMask{
				SpiffeId:  false,
				ParentId:  true,
				Selectors: false,
			},
		},
		{
			name: "fail bad spiffe id",
			entry: &types.Entry{
				Id:       "entry1",
				ParentId: &types.SPIFFEID{TrustDomain: "", Path: "/foo"},
				Selectors: []*types.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
			},
			err: "invalid parent ID: spiffeid: trust domain is empty",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			entry, err := api.ProtoToRegistrationEntryWithMask(tt.entry, tt.mask)
			if tt.err != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.err)
				require.Nil(t, entry)
				return
			}

			require.NoError(t, err)
			spiretest.AssertProtoEqual(t, tt.expectEntry, entry)
		})
	}
}

func TestProtoToRegistrationEntry(t *testing.T) {
	expiresAt := time.Now().Unix()

	for _, tt := range []struct {
		name        string
		entry       *types.Entry
		err         string
		expectEntry *common.RegistrationEntry
	}{
		{
			name: "success",
			entry: &types.Entry{
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
					"domain2.com",
				},
				Admin:      true,
				ExpiresAt:  expiresAt,
				DnsNames:   []string{"dns1", "dns2"},
				Downstream: true,
			},
			expectEntry: &common.RegistrationEntry{
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
		},
		{
			name: "missing entry",
			err:  "missing entry",
		},
		{
			name: "no parent ID",
			err:  "invalid parent ID: request must specify SPIFFE ID",
			entry: &types.Entry{
				SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
			},
		},
		{
			name: "malformed parent ID",
			err:  "invalid parent ID: spiffeid: unable to parse:",
			entry: &types.Entry{
				ParentId: &types.SPIFFEID{TrustDomain: "invalid domain"},
				SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
			},
		},
		{
			name: "no spiffe ID",
			err:  "invalid spiffe ID: request must specify SPIFFE ID",
			entry: &types.Entry{
				ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
			},
		},
		{
			name: "malformed spiffe ID",
			err:  "invalid spiffe ID: spiffeid: unable to parse:",
			entry: &types.Entry{
				SpiffeId: &types.SPIFFEID{TrustDomain: "invalid domain"},
				ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
			},
		},
		{
			name: "invalid DNS name",
			err:  "invalid DNS name: label does not match regex: abc-",
			entry: &types.Entry{
				SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
				ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
				Selectors: []*types.Selector{{Type: "unix", Value: "uid:1000"}},
				DnsNames:  []string{"abc-"},
			},
		},
		{
			name: "malformed federated trust domain",
			err:  "invalid federated trust domain: spiffeid: unable to parse: parse spiffe://malformed td:",
			entry: &types.Entry{
				SpiffeId:      &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
				ParentId:      &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
				Selectors:     []*types.Selector{{Type: "unix", Value: "uid:1000"}},
				FederatesWith: []string{"malformed td"},
			},
		},
		{
			name: "missing selector type",
			entry: &types.Entry{
				ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
				SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
				Selectors: []*types.Selector{
					{Type: "", Value: "uid:1000"},
				},
			},
			err: "missing selector type",
		},
		{
			name: "malformed selector type",
			entry: &types.Entry{
				ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
				SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
				Selectors: []*types.Selector{
					{Type: "unix:uid", Value: "1000"},
				},
			},
			err: "selector type contains ':'",
		},
		{
			name: "missing selector value",
			entry: &types.Entry{
				ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
				SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
				Selectors: []*types.Selector{
					{Type: "unix", Value: ""},
				},
			},
			err: "missing selector value",
		},
		{
			name: "no selectors",
			entry: &types.Entry{
				ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
				SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
				Selectors: []*types.Selector{},
			},
			err: "selector list is empty",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			entry, err := api.ProtoToRegistrationEntry(tt.entry)
			if tt.err != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.err)
				require.Nil(t, entry)

				return
			}

			require.NoError(t, err)
			spiretest.AssertProtoEqual(t, tt.expectEntry, entry)
		})
	}
}
