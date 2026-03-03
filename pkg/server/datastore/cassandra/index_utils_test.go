package cassandra

import (
	"slices"
	"testing"

	datastorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/datastore/v1alpha1"
)

func TestMatchAnySelectorIndexes(t *testing.T) {
	selectors := []*datastorev1.Selector{
		{Type: "a", Value: "1"},
		{Type: "b", Value: "2"},
		{Type: "c", Value: "3"},
	}

	expectedAnyIndexes := []string{
		"stv_match_any_type_a_value_1",
		"stv_match_any_type_b_value_2",
		"stv_match_any_type_c_value_3",
	}

	actualAnyIndexes := buildSelectorAnyMatchIndexes(selectors)

	if len(expectedAnyIndexes) != len(actualAnyIndexes) {
		t.Fatalf("expected %d any match indexes, got %d", len(expectedAnyIndexes), len(actualAnyIndexes))
	}

	for i, expected := range expectedAnyIndexes {
		if expected != actualAnyIndexes[i] {
			t.Errorf("expected any match index %d to be %q, got %q", i, expected, actualAnyIndexes[i])
		}
	}
}

func TestMatchExactSelectorIndex(t *testing.T) {
	selectors := []*datastorev1.Selector{
		{Type: "a", Value: "1"},
	}

	expectedExactIndex := "stv_match_exact_type_a_value_1"
	actualExactIndex := buildSelectorMatchExactIndex(selectors)

	if expectedExactIndex != actualExactIndex {
		t.Errorf("expected exact match index to be %q, got %q", expectedExactIndex, actualExactIndex)
	}
}

func TestMatchSupersetSelectorIndexes(t *testing.T) {
	selectors := []*datastorev1.Selector{
		{Type: "a", Value: "1"},
		{Type: "b", Value: "2"},
	}

	expectedSupersetIndexes := []string{
		"stv_match_superset_type_a_value_1",
		"stv_match_superset_type_b_value_2",
		"stv_match_superset_type_a_value_1_type_b_value_2",
	}

	actualSupersetIndexes := buildSelectorSupersetMatchIndexes(selectors)

	if len(expectedSupersetIndexes) != len(actualSupersetIndexes) {
		t.Fatalf("expected %d superset match indexes, got %d", len(expectedSupersetIndexes), len(actualSupersetIndexes))
	}

	for i, expected := range expectedSupersetIndexes {
		if expected != actualSupersetIndexes[i] {
			t.Errorf("expected superset match index %d to be %q, got %q", i, expected, actualSupersetIndexes[i])
		}
	}
}

func TestMatchExactFederatedTrustDomainIndex(t *testing.T) {
	trustDomains := []string{
		"domain1.test",
		"domain2.test",
		"domain3.test",
	}
	expected := "ftd_match_exact_td_domain1.test__td_domain2.test__td_domain3.test"
	actual := buildFtdExactIndex(trustDomains)

	if expected != actual {
		t.Errorf("expected federated trust domain exact match index to be %q, got %q", expected, actual)
	}
}

func TestMatchAnyFederatedTrustDomainIndexes(t *testing.T) {
	trustDomains := []string{
		"domain1.test",
		"domain2.test",
		"domain3.test",
	}

	expected := []string{
		"ftd_match_any_td_domain1.test",
		"ftd_match_any_td_domain2.test",
		"ftd_match_any_td_domain3.test",
	}

	actual := buildFtdAnyMatchIndexes(trustDomains)

	if len(expected) != len(actual) {
		t.Fatalf("expected %d federated trust domain any match indexes, got %d", len(expected), len(actual))
	}

	for i, exp := range expected {
		if exp != actual[i] {
			t.Errorf("expected federated trust domain any match index %d to be %q, got %q", i, exp, actual[i])
		}
	}
}

func TestMatchSupersetFederatedTrustDomainIndexes(t *testing.T) {
	trustDomains := []string{
		"domain1.test",
		"domain2.test",
	}

	expected := []string{
		"ftd_match_superset_td_domain1.test",
		"ftd_match_superset_td_domain2.test",
		"ftd_match_superset_td_domain1.test__td_domain2.test",
	}

	actual := buildFtdSupersetMatchIndexes(trustDomains)

	if len(expected) != len(actual) {
		t.Fatalf("expected %d federated trust domain superset match indexes, got %d", len(expected), len(actual))
	}

	for i, exp := range expected {
		if exp != actual[i] {
			t.Errorf("expected federated trust domain superset match index %d to be %q, got %q", i, exp, actual[i])
		}
	}
}

func TestCombinations(t *testing.T) {
	cases := []struct {
		els      []string
		expected [][]string
	}{
		{
			els: []string{"a", "b", "c", "d"},
			expected: [][]string{
				{"a"},
				{"b"},
				{"c"},
				{"d"},
				{"a", "b"},
				{"a", "c"},
				{"a", "d"},
				{"a", "b", "c"},
				{"a", "c", "d"},
				{"a", "b", "d"},
				{"a", "b", "c", "d"},
				{"b", "c"},
				{"b", "d"},
				{"b", "c", "d"},
				{"c", "d"},
			},
		},
	}

	for _, c := range cases {
		ret := powerSlice(c.els)
		if len(ret) != len(c.expected) {
			t.Fatalf("unxepected length")
		}

		for _, v := range ret {
			expected := false
			for _, w := range c.expected {
				if slices.Equal(w, v) {
					expected = true
					break
				}
			}

			if !expected {
				t.Fatalf("expected to find %v in %v", v, c.expected)
			}
		}
	}
}
