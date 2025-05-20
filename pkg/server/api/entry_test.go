package api_test

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/protoutil"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
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
				EntryId:     "entry1",
				ParentId:    "spiffe://example.org/foo",
				SpiffeId:    "spiffe://example.org/bar",
				X509SvidTtl: 70,
				JwtSvidTtl:  80,
				Selectors: []*common.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
				FederatesWith: []string{
					"spiffe://domain1.com",
					// common registration entries use the trust domain ID, but
					// we should assert that they are normalized to trust
					// domain name either way.
					"domain2.com",
				},
				Admin:          true,
				EntryExpiry:    expiresAt,
				DnsNames:       []string{"dns1", "dns2"},
				Downstream:     true,
				RevisionNumber: 99,
				Hint:           "external",
				CreatedAt:      1678731397,
			},
			expectEntry: &types.Entry{
				Id:          "entry1",
				ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
				SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
				X509SvidTtl: 70,
				JwtSvidTtl:  80,
				Selectors: []*types.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
				FederatesWith: []string{
					"domain1.com",
					"domain2.com",
				},
				Admin:          true,
				ExpiresAt:      expiresAt,
				DnsNames:       []string{"dns1", "dns2"},
				Downstream:     true,
				RevisionNumber: 99,
				Hint:           "external",
				CreatedAt:      1678731397,
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
			err: "invalid parent ID: scheme is missing or invalid",
		},
		{
			name: "malformed SpiffeId",
			entry: &common.RegistrationEntry{
				ParentId: "spiffe://example.org/foo",
				SpiffeId: "malformed SpiffeID",
			},
			err: "invalid SPIFFE ID: scheme is missing or invalid",
		},
	} {
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
	td := spiffeid.RequireTrustDomainFromString("example.org")
	expiresAt := time.Now().Unix()

	for _, tt := range []struct {
		name        string
		entry       *types.Entry
		err         string
		expectEntry *common.RegistrationEntry
		mask        *types.EntryMask
	}{
		{
			name: "mask including all fields",
			entry: &types.Entry{
				Id:          "entry1",
				ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
				SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
				X509SvidTtl: 70,
				JwtSvidTtl:  80,
				Selectors: []*types.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
				FederatesWith: []string{
					"domain1.com",
					// types entries use the trust domain name, but we should
					// assert that they are normalized to trust domain ID
					// either way.
					"spiffe://domain2.com",
				},
				Admin:          true,
				ExpiresAt:      expiresAt,
				DnsNames:       []string{"dns1", "dns2"},
				Downstream:     true,
				RevisionNumber: 99,
				Hint:           strings.Repeat("a", 1024),
			},
			expectEntry: &common.RegistrationEntry{
				EntryId:     "entry1",
				ParentId:    "spiffe://example.org/foo",
				SpiffeId:    "spiffe://example.org/bar",
				X509SvidTtl: 70,
				JwtSvidTtl:  80,
				Selectors: []*common.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
				FederatesWith: []string{
					"spiffe://domain1.com",
					"spiffe://domain2.com",
				},
				Admin:          true,
				EntryExpiry:    expiresAt,
				DnsNames:       []string{"dns1", "dns2"},
				Downstream:     true,
				RevisionNumber: 99,
				Hint:           strings.Repeat("a", 1024),
			},
			mask: protoutil.AllTrueEntryMask,
		},
		{
			name: "mask off all fields",
			entry: &types.Entry{
				Id:             "entry1",
				ParentId:       &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
				Selectors:      []*types.Selector{},
				DnsNames:       []string{"name1"},
				FederatesWith:  []string{"domain.test"},
				X509SvidTtl:    2,
				JwtSvidTtl:     3,
				Admin:          true,
				Downstream:     true,
				ExpiresAt:      4,
				RevisionNumber: 99,
			},
			expectEntry: &common.RegistrationEntry{
				EntryId: "entry1",
			},
			mask: &types.EntryMask{},
		},
		{
			name: "invalid parent id",
			entry: &types.Entry{
				Id:          "entry1",
				ParentId:    &types.SPIFFEID{TrustDomain: "invalid", Path: "/foo"},
				SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
				X509SvidTtl: 70,
				JwtSvidTtl:  80,
				Selectors: []*types.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
				FederatesWith: []string{
					"domain1.com",
					// types entries use the trust domain name, but we should
					// assert that they are normalized to trust domain ID
					// either way.
					"spiffe://domain2.com",
				},
				Admin:          true,
				ExpiresAt:      expiresAt,
				DnsNames:       []string{"dns1", "dns2"},
				Downstream:     true,
				RevisionNumber: 99,
				Hint:           "external",
			},
			expectEntry: &common.RegistrationEntry{
				EntryId:     "entry1",
				ParentId:    "spiffe://example.org/foo",
				SpiffeId:    "spiffe://example.org/bar",
				X509SvidTtl: 70,
				JwtSvidTtl:  80,
				Selectors: []*common.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
				FederatesWith: []string{
					"spiffe://domain1.com",
					"spiffe://domain2.com",
				},
				Admin:          true,
				EntryExpiry:    expiresAt,
				DnsNames:       []string{"dns1", "dns2"},
				Downstream:     true,
				RevisionNumber: 99,
				Hint:           "external",
			},
			mask: protoutil.AllTrueEntryMask,
			err:  "invalid parent ID: \"spiffe://invalid/foo\" is not a member of trust domain \"example.org\"",
		},
		{
			name: "invalid spiffe id",
			entry: &types.Entry{
				Id:          "entry1",
				ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
				SpiffeId:    &types.SPIFFEID{TrustDomain: "invalid", Path: "/bar"},
				X509SvidTtl: 70,
				JwtSvidTtl:  80,
				Selectors: []*types.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
				FederatesWith: []string{
					"domain1.com",
					// types entries use the trust domain name, but we should
					// assert that they are normalized to trust domain ID
					// either way.
					"spiffe://domain2.com",
				},
				Admin:          true,
				ExpiresAt:      expiresAt,
				DnsNames:       []string{"dns1", "dns2"},
				Downstream:     true,
				RevisionNumber: 99,
				Hint:           "external",
			},
			expectEntry: &common.RegistrationEntry{
				EntryId:     "entry1",
				ParentId:    "spiffe://example.org/foo",
				SpiffeId:    "spiffe://example.org/bar",
				X509SvidTtl: 70,
				JwtSvidTtl:  80,
				Selectors: []*common.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
				FederatesWith: []string{
					"spiffe://domain1.com",
					"spiffe://domain2.com",
				},
				Admin:          true,
				EntryExpiry:    expiresAt,
				DnsNames:       []string{"dns1", "dns2"},
				Downstream:     true,
				RevisionNumber: 99,
				Hint:           "external",
			},
			mask: protoutil.AllTrueEntryMask,
			err:  "invalid spiffe ID: \"spiffe://invalid/bar\" is not a member of trust domain \"example.org\"",
		},
		{
			name: "invalid dns names",
			entry: &types.Entry{
				Id:          "entry1",
				ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
				SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
				X509SvidTtl: 70,
				JwtSvidTtl:  80,
				Selectors: []*types.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
				FederatesWith: []string{
					"domain1.com",
					// types entries use the trust domain name, but we should
					// assert that they are normalized to trust domain ID
					// either way.
					"spiffe://domain2.com",
				},
				Admin:          true,
				ExpiresAt:      expiresAt,
				DnsNames:       []string{""},
				Downstream:     true,
				RevisionNumber: 99,
				Hint:           "external",
			},
			expectEntry: &common.RegistrationEntry{
				EntryId:     "entry1",
				ParentId:    "spiffe://example.org/foo",
				SpiffeId:    "spiffe://example.org/bar",
				X509SvidTtl: 70,
				JwtSvidTtl:  80,
				Selectors: []*common.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
				FederatesWith: []string{
					"spiffe://domain1.com",
					"spiffe://domain2.com",
				},
				Admin:          true,
				EntryExpiry:    expiresAt,
				DnsNames:       []string{"dns1", "dns2"},
				Downstream:     true,
				RevisionNumber: 99,
				Hint:           "external",
			},
			mask: protoutil.AllTrueEntryMask,
			err:  "invalid DNS name: empty or only whitespace",
		},
		{
			name: "invalid federates with",
			entry: &types.Entry{
				Id:          "entry1",
				ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
				SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
				X509SvidTtl: 70,
				JwtSvidTtl:  80,
				Selectors: []*types.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
				FederatesWith: []string{
					"",
				},
				Admin:          true,
				ExpiresAt:      expiresAt,
				DnsNames:       []string{"dns1", "dns2"},
				Downstream:     true,
				RevisionNumber: 99,
				Hint:           "external",
			},
			expectEntry: &common.RegistrationEntry{
				EntryId:     "entry1",
				ParentId:    "spiffe://example.org/foo",
				SpiffeId:    "spiffe://example.org/bar",
				X509SvidTtl: 70,
				JwtSvidTtl:  80,
				Selectors: []*common.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
				FederatesWith: []string{
					"spiffe://domain1.com",
					"spiffe://domain2.com",
				},
				Admin:          true,
				EntryExpiry:    expiresAt,
				DnsNames:       []string{"dns1", "dns2"},
				Downstream:     true,
				RevisionNumber: 99,
				Hint:           "external",
			},
			mask: protoutil.AllTrueEntryMask,
			err:  "invalid federated trust domain: trust domain is missing",
		},
		{
			name: "invalid selectors",
			entry: &types.Entry{
				Id:          "entry1",
				ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
				SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
				X509SvidTtl: 70,
				JwtSvidTtl:  80,
				Selectors:   []*types.Selector{},
				FederatesWith: []string{
					"domain1.com",
					// types entries use the trust domain name, but we should
					// assert that they are normalized to trust domain ID
					// either way.
					"spiffe://domain2.com",
				},
				Admin:          true,
				ExpiresAt:      expiresAt,
				DnsNames:       []string{"dns1", "dns2"},
				Downstream:     true,
				RevisionNumber: 99,
				Hint:           "external",
			},
			expectEntry: &common.RegistrationEntry{
				EntryId:     "entry1",
				ParentId:    "spiffe://example.org/foo",
				SpiffeId:    "spiffe://example.org/bar",
				X509SvidTtl: 70,
				JwtSvidTtl:  80,
				Selectors: []*common.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
				FederatesWith: []string{
					"spiffe://domain1.com",
					"spiffe://domain2.com",
				},
				Admin:          true,
				EntryExpiry:    expiresAt,
				DnsNames:       []string{"dns1", "dns2"},
				Downstream:     true,
				RevisionNumber: 99,
				Hint:           "external",
			},
			mask: protoutil.AllTrueEntryMask,
			err:  "selector list is empty",
		},
		{
			name: "invalid hint",
			entry: &types.Entry{
				Id:          "entry1",
				ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
				SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
				X509SvidTtl: 70,
				JwtSvidTtl:  80,
				Selectors: []*types.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
				FederatesWith: []string{
					"domain1.com",
					// types entries use the trust domain name, but we should
					// assert that they are normalized to trust domain ID
					// either way.
					"spiffe://domain2.com",
				},
				Admin:          true,
				ExpiresAt:      expiresAt,
				DnsNames:       []string{"dns1", "dns2"},
				Downstream:     true,
				RevisionNumber: 99,
				Hint:           strings.Repeat("a", 1025),
			},
			mask: protoutil.AllTrueEntryMask,
			err:  "hint is too long, max length is 1024 characters",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := api.ProtoToRegistrationEntryWithMask(context.Background(), td, tt.entry, tt.mask)
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
	td := spiffeid.RequireTrustDomainFromString("example.org")
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
				Id:          "entry1",
				ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
				SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
				X509SvidTtl: 70,
				JwtSvidTtl:  80,
				Selectors: []*types.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
				FederatesWith: []string{
					"domain1.com",
					// types entries use the trust domain name, but we should
					// assert that they are normalized to trust domain ID
					// either way.
					"spiffe://domain2.com",
				},
				Admin:          true,
				ExpiresAt:      expiresAt,
				DnsNames:       []string{"dns1", "dns2"},
				Downstream:     true,
				RevisionNumber: 99,
				Hint:           "external",
			},
			expectEntry: &common.RegistrationEntry{
				EntryId:     "entry1",
				ParentId:    "spiffe://example.org/foo",
				SpiffeId:    "spiffe://example.org/bar",
				X509SvidTtl: 70,
				JwtSvidTtl:  80,
				Selectors: []*common.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
				FederatesWith: []string{
					"spiffe://domain1.com",
					"spiffe://domain2.com",
				},
				Admin:          true,
				EntryExpiry:    expiresAt,
				DnsNames:       []string{"dns1", "dns2"},
				Downstream:     true,
				RevisionNumber: 99,
				Hint:           "external",
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
			err:  "invalid parent ID: trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
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
			err:  "invalid spiffe ID: trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
			entry: &types.Entry{
				SpiffeId: &types.SPIFFEID{TrustDomain: "invalid domain"},
				ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
			},
		},
		{
			name: "invalid DNS name",
			err:  "idna error",
			entry: &types.Entry{
				SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
				ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
				Selectors: []*types.Selector{{Type: "unix", Value: "uid:1000"}},
				DnsNames:  []string{"abc-"},
			},
		},
		{
			name: "malformed federated trust domain",
			err:  "invalid federated trust domain: trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
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
		t.Run(tt.name, func(t *testing.T) {
			entry, err := api.ProtoToRegistrationEntry(context.Background(), td, tt.entry)
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

func TestReadOnlyEntryIsReadOnly(t *testing.T) {
	expiresAt := time.Now().Unix()
	entry := &types.Entry{
		Id:          "entry1",
		ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
		SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
		X509SvidTtl: 70,
		JwtSvidTtl:  80,
		Selectors: []*types.Selector{
			{Type: "unix", Value: "uid:1000"},
			{Type: "unix", Value: "gid:1000"},
		},
		FederatesWith: []string{
			"domain1.com",
			"domain2.com",
		},
		Admin:          true,
		ExpiresAt:      expiresAt,
		DnsNames:       []string{"dns1", "dns2"},
		Downstream:     true,
		RevisionNumber: 99,
		Hint:           "external",
		CreatedAt:      1678731397,
		StoreSvid:      true,
	}
	readOnlyEntry := api.NewReadOnlyEntry(entry)

	clonedEntry := readOnlyEntry.Clone(protoutil.AllTrueEntryMask)
	clonedEntry.Admin = false
	clonedEntry.DnsNames = nil

	require.NotEqual(t, entry.DnsNames, clonedEntry.DnsNames)
	require.NotEqual(t, entry.Admin, clonedEntry.Admin)
}

func TestReadOnlyEntry(t *testing.T) {
	expiresAt := time.Now().Unix()
	entry := &types.Entry{
		Id:          "entry1",
		ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
		SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
		X509SvidTtl: 70,
		JwtSvidTtl:  80,
		Selectors: []*types.Selector{
			{Type: "unix", Value: "uid:1000"},
			{Type: "unix", Value: "gid:1000"},
		},
		FederatesWith: []string{
			"domain1.com",
			"domain2.com",
		},
		Admin:          true,
		ExpiresAt:      expiresAt,
		DnsNames:       []string{"dns1", "dns2"},
		Downstream:     true,
		RevisionNumber: 99,
		Hint:           "external",
		CreatedAt:      1678731397,
		StoreSvid:      true,
	}

	// Verify that all getters return the expected value
	readOnlyEntry := api.NewReadOnlyEntry(entry)
	require.Equal(t, readOnlyEntry.GetId(), entry.Id)
	require.Equal(t, readOnlyEntry.GetSpiffeId(), entry.SpiffeId)
	require.Equal(t, readOnlyEntry.GetX509SvidTtl(), entry.X509SvidTtl)
	require.Equal(t, readOnlyEntry.GetJwtSvidTtl(), entry.JwtSvidTtl)
	require.Equal(t, readOnlyEntry.GetDnsNames(), entry.DnsNames)
	require.Equal(t, readOnlyEntry.GetRevisionNumber(), entry.RevisionNumber)
	require.Equal(t, readOnlyEntry.GetCreatedAt(), entry.CreatedAt)
}

func TestReadOnlyEntryClone(t *testing.T) {
	expiresAt := time.Now().Unix()
	entry := &types.Entry{
		Id:          "entry1",
		ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
		SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
		X509SvidTtl: 70,
		JwtSvidTtl:  80,
		Selectors: []*types.Selector{
			{Type: "unix", Value: "uid:1000"},
			{Type: "unix", Value: "gid:1000"},
		},
		FederatesWith: []string{
			"domain1.com",
			"domain2.com",
		},
		Admin:          true,
		ExpiresAt:      expiresAt,
		DnsNames:       []string{"dns1", "dns2"},
		Downstream:     true,
		RevisionNumber: 99,
		Hint:           "external",
		CreatedAt:      1678731397,
		StoreSvid:      true,
	}

	// Verify that we our test entry has all fields set to make sure
	// the Clone method doesn't miss any new fields.
	value := reflect.ValueOf(entry).Elem()
	valueType := value.Type()
	for i := range value.NumField() {
		fieldType := valueType.Field(i)
		fieldValue := value.Field(i)
		// Skip the protobuf internal fields
		if strings.HasPrefix(fieldType.Name, "XXX_") {
			continue
		}
		if slices.Index([]string{"state", "sizeCache", "unknownFields"}, fieldType.Name) != -1 {
			continue
		}

		require.False(t, fieldValue.IsZero(), "Field '%s' is not set", value.Type().Field(i).Name)
	}

	readOnlyEntry := api.NewReadOnlyEntry(entry)

	protoClone := proto.Clone(entry).(*types.Entry)
	readOnlyClone := readOnlyEntry.Clone(protoutil.AllTrueEntryMask)

	spiretest.AssertProtoEqual(t, protoClone, readOnlyClone)
}

func BenchmarkEntryClone(b *testing.B) {
	expiresAt := time.Now().Unix()
	entry := &types.Entry{
		Id:          "entry1",
		ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
		SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
		X509SvidTtl: 70,
		JwtSvidTtl:  80,
		Selectors: []*types.Selector{
			{Type: "unix", Value: "uid:1000"},
			{Type: "unix", Value: "gid:1000"},
		},
		FederatesWith: []string{
			"domain1.com",
			"domain2.com",
		},
		Admin:          true,
		ExpiresAt:      expiresAt,
		DnsNames:       []string{"dns1", "dns2"},
		Downstream:     true,
		RevisionNumber: 99,
		Hint:           "external",
		CreatedAt:      1678731397,
		StoreSvid:      true,
	}

	for b.Loop() {
		_ = proto.Clone(entry).(*types.Entry)
	}
}

func BenchmarkReadOnlyEntryClone(b *testing.B) {
	expiresAt := time.Now().Unix()
	entry := &types.Entry{
		Id:          "entry1",
		ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
		SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
		X509SvidTtl: 70,
		JwtSvidTtl:  80,
		Selectors: []*types.Selector{
			{Type: "unix", Value: "uid:1000"},
			{Type: "unix", Value: "gid:1000"},
		},
		FederatesWith: []string{
			"domain1.com",
			"domain2.com",
		},
		Admin:          true,
		ExpiresAt:      expiresAt,
		DnsNames:       []string{"dns1", "dns2"},
		Downstream:     true,
		RevisionNumber: 99,
		Hint:           "external",
		CreatedAt:      1678731397,
		StoreSvid:      true,
	}
	readOnlyEntry := api.NewReadOnlyEntry(entry)
	allTrueMask := protoutil.AllTrueEntryMask

	for b.Loop() {
		_ = readOnlyEntry.Clone(allTrueMask)
	}
}
