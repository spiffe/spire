package api

import (
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestReferenceMessageName(t *testing.T) {
	assert.Equal(t, "spire.api.types.SelectorReference", referenceMessageName(SelectorReferenceTypeURL))
	assert.Equal(t, "spire.api.types.SelectorReference", referenceMessageName(nonCanonicalSelectorType))
	// A bare message name with no prefix is returned unchanged.
	assert.Equal(t, "spire.api.types.SelectorReference", referenceMessageName("spire.api.types.SelectorReference"))
	assert.Equal(t, "spiffe.broker.WorkloadPIDReference", referenceMessageName("type.googleapis.com/spiffe.broker.WorkloadPIDReference"))
	assert.Equal(t, "", referenceMessageName(""))
}

func TestIsSelectorReference(t *testing.T) {
	assert.True(t, isSelectorReference(SelectorReferenceTypeURL))
	// anypb resolves by message name, so a non-canonical prefix is still a
	// selector reference and must be gated as one.
	assert.True(t, isSelectorReference(nonCanonicalSelectorType))
	assert.False(t, isSelectorReference(k8sType))
	assert.False(t, isSelectorReference(""))
	// A different message in the same package must not match.
	assert.False(t, isSelectorReference("type.googleapis.com/spire.api.types.SelectorReferenceOther"))
}

func TestRequiresExplicitGrant(t *testing.T) {
	assert.True(t, requiresExplicitGrant(SelectorReferenceTypeURL))
	assert.True(t, requiresExplicitGrant(nonCanonicalSelectorType))
	assert.False(t, requiresExplicitGrant(k8sType))
	assert.False(t, requiresExplicitGrant(pidType))
}

// selectorRef packs selectors into an Any as a SelectorReference.
func selectorRef(t *testing.T, selectors ...*types.Selector) *anypb.Any {
	t.Helper()
	packed, err := anypb.New(&types.SelectorReference{Selectors: selectors})
	require.NoError(t, err)
	return packed
}

func sel(selectorType, value string) *types.Selector {
	return &types.Selector{Type: selectorType, Value: value}
}

func TestSelectorsFromSelectorReference(t *testing.T) {
	caller := spiffeid.RequireFromString("spiffe://example.org/broker")
	other := spiffeid.RequireFromString("spiffe://example.org/other")

	k8sOnly := map[spiffeid.ID]SelectorAssertionPolicy{caller: {
		AllowedSelectorTypes: map[string]struct{}{"k8s_psat": {}},
	}}

	for _, tt := range []struct {
		name            string
		selByCaller     map[spiffeid.ID]SelectorAssertionPolicy
		caller          spiffeid.ID
		ref             *anypb.Any
		expectCode      codes.Code
		expectSelectors []*common.Selector
	}{
		{
			name:        "resolves asserted selectors",
			selByCaller: k8sOnly,
			caller:      caller,
			ref:         selectorRef(t, sel("k8s_psat", "ns:default"), sel("k8s_psat", "pod-name:foo")),
			expectCode:  codes.OK,
			expectSelectors: []*common.Selector{
				{Type: "k8s_psat", Value: "ns:default"},
				{Type: "k8s_psat", Value: "pod-name:foo"},
			},
		},
		{
			name:        "malformed reference payload is rejected",
			selByCaller: k8sOnly,
			caller:      caller,
			ref:         &anypb.Any{TypeUrl: SelectorReferenceTypeURL, Value: []byte("not a protobuf")},
			expectCode:  codes.InvalidArgument,
		},
		{
			// An empty set matches no cache records, which would otherwise
			// surface as an empty stream or a misleading "no identity issued".
			name:        "empty selector set is rejected explicitly",
			selByCaller: k8sOnly,
			caller:      caller,
			ref:         selectorRef(t),
			expectCode:  codes.InvalidArgument,
		},
		{
			name: "selector count over the cap is rejected",
			selByCaller: map[spiffeid.ID]SelectorAssertionPolicy{caller: {
				AllowedSelectorTypes: map[string]struct{}{"k8s_psat": {}},
				MaxSelectors:         1,
			}},
			caller:     caller,
			ref:        selectorRef(t, sel("k8s_psat", "ns:default"), sel("k8s_psat", "pod-name:foo")),
			expectCode: codes.InvalidArgument,
		},
		{
			name:        "empty selector type is rejected",
			selByCaller: k8sOnly,
			caller:      caller,
			ref:         selectorRef(t, sel("", "ns:default")),
			expectCode:  codes.InvalidArgument,
		},
		{
			name:        "empty selector value is rejected",
			selByCaller: k8sOnly,
			caller:      caller,
			ref:         selectorRef(t, sel("k8s_psat", "")),
			expectCode:  codes.InvalidArgument,
		},
		{
			name:        "selector type containing a colon is rejected",
			selByCaller: k8sOnly,
			caller:      caller,
			ref:         selectorRef(t, sel("k8s_psat:ns", "default")),
			expectCode:  codes.InvalidArgument,
		},
		{
			name:        "disallowed selector type is rejected",
			selByCaller: k8sOnly,
			caller:      caller,
			ref:         selectorRef(t, sel("unix", "uid:0")),
			expectCode:  codes.PermissionDenied,
		},
		{
			// Fails on the first disallowed type; nothing is partially
			// resolved.
			name:        "mixed allowed and disallowed selector types is rejected",
			selByCaller: k8sOnly,
			caller:      caller,
			ref:         selectorRef(t, sel("k8s_psat", "ns:default"), sel("unix", "uid:0")),
			expectCode:  codes.PermissionDenied,
		},
		{
			name: "caller with an empty selector type allowlist is denied",
			selByCaller: map[spiffeid.ID]SelectorAssertionPolicy{caller: {
				AllowedSelectorTypes: map[string]struct{}{},
			}},
			caller:     caller,
			ref:        selectorRef(t, sel("k8s_psat", "ns:default")),
			expectCode: codes.PermissionDenied,
		},
		{
			name: "caller absent from the policy map is denied",
			selByCaller: map[spiffeid.ID]SelectorAssertionPolicy{other: {
				AllowedSelectorTypes: map[string]struct{}{"k8s_psat": {}},
			}},
			caller:     caller,
			ref:        selectorRef(t, sel("k8s_psat", "ns:default")),
			expectCode: codes.PermissionDenied,
		},
		{
			name:        "nil policy map denies everything",
			selByCaller: nil,
			caller:      caller,
			ref:         selectorRef(t, sel("k8s_psat", "ns:default")),
			expectCode:  codes.PermissionDenied,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			log, _ := test.NewNullLogger()
			s := New(Config{SelectorAssertionByCaller: tt.selByCaller})

			selectors, err := s.selectorsFromSelectorReference(udsContext(), log, tt.caller, tt.ref)
			if tt.expectCode == codes.OK {
				require.NoError(t, err)
				spiretest.AssertProtoListEqual(t, tt.expectSelectors, selectors)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tt.expectCode, status.Code(err))
			assert.Nil(t, selectors)
		})
	}
}

// TestSelectorsFromSelectorReferenceDefaultsMaxSelectors verifies that a policy
// with no explicit cap falls back to the default rather than rejecting
// everything.
func TestSelectorsFromSelectorReferenceDefaultsMaxSelectors(t *testing.T) {
	caller := spiffeid.RequireFromString("spiffe://example.org/broker")
	log, _ := test.NewNullLogger()
	s := New(Config{SelectorAssertionByCaller: map[spiffeid.ID]SelectorAssertionPolicy{caller: {
		AllowedSelectorTypes: map[string]struct{}{"k8s_psat": {}},
	}}})

	selectors := make([]*types.Selector, 0, DefaultMaxAssertedSelectors)
	for i := range DefaultMaxAssertedSelectors {
		selectors = append(selectors, sel("k8s_psat", "pod-label:n"+string(rune('a'+i%26))))
	}

	got, err := s.selectorsFromSelectorReference(udsContext(), log, caller, selectorRef(t, selectors...))
	require.NoError(t, err)
	assert.Len(t, got, DefaultMaxAssertedSelectors)

	// One over the default is rejected.
	selectors = append(selectors, sel("k8s_psat", "ns:default"))
	_, err = s.selectorsFromSelectorReference(udsContext(), log, caller, selectorRef(t, selectors...))
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestCallerTransport(t *testing.T) {
	assert.Equal(t, "uds", callerTransport(udsContext()))
	assert.Equal(t, "tcp", callerTransport(tcpContext()))
}
