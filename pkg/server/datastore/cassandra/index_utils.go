package cassandra

import (
	"math"
	"strings"

	datastorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/datastore/v1alpha1"
	"github.com/spiffe/spire/pkg/server/datastore/cassandra/qb"
)

func powerSlice[T any](els []T) [][]T {
	if len(els) == 0 {
		return [][]T{}
	}

	results := [][]T{}

	count := int(math.Pow(2, float64(len(els))))

	for i := range count {
		subset := []T{}

		for j := range len(els) {
			if (i & (1 << j)) > 0 {
				subset = append(subset, els[j])
			}
		}

		if len(subset) > 0 {
			results = append(results, subset)
		}
	}

	return results
}

func generateSelectorFilters(req *datastorev1.BySelectors, q qb.SelectBuilder) (needsExtraColumn bool) {
	if req == nil {
		return
	}

	switch req.MatchBehavior {
	case datastorev1.MatchBehavior_MATCH_BEHAVIOR_MATCH_EXACT:
		q.Where("index_terms", qb.Contains(buildSelectorMatchExactIndex(req.Selectors)))
		q.Distinct()
	case datastorev1.MatchBehavior_MATCH_BEHAVIOR_MATCH_SUBSET:
		selectors := make([]any, len(req.Selectors))

		for i, sl := range req.Selectors {
			b := strings.Builder{}
			b.WriteString(sl.Type)
			b.WriteString("|")
			b.WriteString(sl.Value)
			selectors[i] = b.String()
		}

		vals := powerSlice(selectors)

		q.Where("selector_type_value_full", qb.CollectionIn(vals...))
		q.Distinct()
	case datastorev1.MatchBehavior_MATCH_BEHAVIOR_MATCH_ANY:
		vals := make([]any, len(req.Selectors))
		for i, sl := range req.Selectors {
			b := strings.Builder{}
			b.WriteString(sl.Type)
			b.WriteString("|")
			b.WriteString(sl.Value)
			vals[i] = b.String()
		}

		q.Where("selector_type_value", qb.In(vals...))
		return true
	case datastorev1.MatchBehavior_MATCH_BEHAVIOR_MATCH_SUPERSET:
		b := strings.Builder{}
		b.WriteString(selectorMatchPrefix)
		b.WriteString(matcherSupersetInfix)

		for i, sl := range req.Selectors {
			if i > 0 {
				b.WriteString("__")
			}
			b.WriteString("type_")
			b.WriteString(sl.Type)
			b.WriteString("_value_")
			b.WriteString(sl.Value)
		}

		q.Distinct().Where("index_terms", qb.Contains(b.String()))
	}

	return
}

func generateSearchIndexesForRequest(req *datastorev1.ListRegistrationEntriesRequest) []queryTerm {
	var indices []queryTerm
	if req.BySelectors != nil {
		switch req.BySelectors.MatchBehavior {
		case datastorev1.MatchBehavior_MATCH_BEHAVIOR_MATCH_EXACT:
			indices = append(indices, queryTerm{
				field:           "index_terms",
				operator:        "CONTAINS",
				values:          []any{buildSelectorMatchExactIndex(req.BySelectors.Selectors)},
				requireDistinct: true,
			})
		case datastorev1.MatchBehavior_MATCH_BEHAVIOR_MATCH_SUBSET:
			selectors := make([]any, len(req.BySelectors.Selectors))

			for i, sl := range req.BySelectors.Selectors {
				b := strings.Builder{}
				b.WriteString(sl.Type)
				b.WriteString("|")
				b.WriteString(sl.Value)
				selectors[i] = b.String()
			}

			vals := powerSlice(selectors)

			indices = append(indices, queryTerm{
				field:           "selector_type_value_full",
				operator:        "IN",
				deepValues:      vals,
				requireDistinct: true,
			})
		case datastorev1.MatchBehavior_MATCH_BEHAVIOR_MATCH_ANY:
			vals := make([]any, len(req.BySelectors.Selectors))
			for i, sl := range req.BySelectors.Selectors {
				b := strings.Builder{}
				b.WriteString(sl.Type)
				b.WriteString("|")
				b.WriteString(sl.Value)
				vals[i] = b.String()
			}

			indices = append(indices, queryTerm{
				field:              "unrolled_selector_type_val",
				operator:           "IN",
				values:             vals,
				includeExtraColumn: true,
			})
		case datastorev1.MatchBehavior_MATCH_BEHAVIOR_MATCH_SUPERSET:
			b := strings.Builder{}
			b.WriteString(selectorMatchPrefix)
			b.WriteString(matcherSupersetInfix)

			for i, sl := range req.BySelectors.Selectors {
				if i > 0 {
					b.WriteString("__")
				}
				b.WriteString("type_")
				b.WriteString(sl.Type)
				b.WriteString("_value_")
				b.WriteString(sl.Value)
			}

			indices = append(indices, queryTerm{
				field:           "index_terms",
				operator:        "CONTAINS",
				values:          []any{b.String()},
				requireDistinct: true,
			})
		}
	}

	if req.ByFederatesWith != nil {
		switch req.ByFederatesWith.MatchBehavior {
		case datastorev1.MatchBehavior_MATCH_BEHAVIOR_MATCH_EXACT:
			indices = append(indices, queryTerm{
				field:           "index_terms",
				operator:        "CONTAINS",
				values:          []any{buildFtdExactIndex(req.ByFederatesWith.FederatesWith)},
				requireDistinct: true,
			})
		case datastorev1.MatchBehavior_MATCH_BEHAVIOR_MATCH_SUBSET:
			tds := make([]any, len(req.ByFederatesWith.FederatesWith))
			for i, td := range req.ByFederatesWith.FederatesWith {
				tds[i] = td
			}

			vals := powerSlice(tds)
			indices = append(indices, queryTerm{
				field:           "federated_trust_domains_full",
				operator:        "IN",
				deepValues:      vals,
				requireDistinct: true,
			})
		case datastorev1.MatchBehavior_MATCH_BEHAVIOR_MATCH_ANY:
			vals := make([]any, len(req.ByFederatesWith.FederatesWith))
			for i, td := range req.ByFederatesWith.FederatesWith {
				vals[i] = td
			}

			indices = append(indices, queryTerm{
				field:              "unrolled_ftd",
				operator:           "IN",
				values:             vals,
				includeExtraColumn: true,
			})
		case datastorev1.MatchBehavior_MATCH_BEHAVIOR_MATCH_SUPERSET:
			b := strings.Builder{}
			b.WriteString(ftdIndexPrefix)
			b.WriteString(matcherSupersetInfix)
			for i, td := range req.ByFederatesWith.FederatesWith {
				if i > 0 {
					b.WriteString("__")
				}
				b.WriteString("td_")
				b.WriteString(td)
			}

			indices = append(indices, queryTerm{
				field:           "index_terms",
				operator:        "CONTAINS",
				values:          []any{b.String()},
				requireDistinct: true,
			})
		}
	}

	return indices
}

const ftdIndexPrefix = "ftd_"
const multipartIndexPrefix = "mpidx__"

func buildIndexesForRegistrationEntry(re *datastorev1.RegistrationEntry) (indexes []string) {
	var sls, tds []string
	if len(re.GetSelectors()) > 0 {
		sls = buildSelectorIndexes(re.GetSelectors())
		indexes = append(indexes, sls...)
	}

	if len(re.GetFederatesWith()) > 0 {
		tds = buildFtdIndexes(re.GetFederatesWith())
		indexes = append(indexes, tds...)
	}

	for _, s := range sls {
		for _, t := range tds {
			b := strings.Builder{}
			b.WriteString(multipartIndexPrefix)
			b.WriteString(s)
			b.WriteString("___")
			b.WriteString(t)

			indexes = append(indexes, b.String())
		}
	}

	return
}

func buildFtdIndexes(trustDomains []string) (indexes []string) {
	indexes = append(indexes, buildFtdAnyMatchIndexes(trustDomains)...)
	indexes = append(indexes, buildFtdExactIndex(trustDomains))
	indexes = append(indexes, buildFtdSupersetMatchIndexes(trustDomains)...)

	return
}

func buildFtdExactIndex(trustDomains []string) string {
	b := strings.Builder{}
	b.WriteString(ftdIndexPrefix)
	b.WriteString(matcherExactInfix)
	for i, td := range trustDomains {
		if i > 0 {
			b.WriteString("__")
		}
		b.WriteString("td_")
		b.WriteString(td)
	}

	return b.String()
}

func buildFtdAnyMatchIndexes(trustDomains []string) []string {
	indexes := make([]string, 0, len(trustDomains))

	for _, td := range trustDomains {
		b := strings.Builder{}
		b.WriteString(ftdIndexPrefix)
		b.WriteString(matcherAnyInfix)
		b.WriteString("td_")
		b.WriteString(td)

		indexes = append(indexes, b.String())
	}

	return indexes
}

func buildFtdSupersetMatchIndexes(trustDomains []string) []string {
	powerset := powerSlice(trustDomains)

	indexes := make([]string, 0, len(trustDomains))

	for _, subset := range powerset {
		b := strings.Builder{}
		b.WriteString(ftdIndexPrefix)
		b.WriteString(matcherSupersetInfix)

		for i, sub := range subset {
			if i > 0 {
				b.WriteString("__")
			}
			b.WriteString("td_")
			b.WriteString(sub)
		}

		indexes = append(indexes, b.String())
	}

	return indexes
}

func buildSelectorIndexes(selectors []*datastorev1.Selector) (indexes []string) {
	indexes = append(indexes, buildSelectorAnyMatchIndexes(selectors)...)
	indexes = append(indexes, buildSelectorMatchExactIndex(selectors))
	indexes = append(indexes, buildSelectorSupersetMatchIndexes(selectors)...)
	// subset is implemented as "in these, but no others": see filterEntriesBySelectorSet in pkg/server/datastore/sqlstore/sqlstore.go

	return
}

const (
	selectorMatchPrefix  = "stv_"
	matcherAnyInfix      = "match_any_"
	matcherExactInfix    = "match_exact_"
	matcherSupersetInfix = "match_superset_"
)

func buildSelectorAnyMatchIndexes(selectors []*datastorev1.Selector) []string {
	indexes := make([]string, 0, len(selectors))

	for _, s := range selectors {
		b := strings.Builder{}
		b.WriteString(selectorMatchPrefix)
		b.WriteString(matcherAnyInfix)
		b.WriteString("type_")
		b.WriteString(s.Type)
		b.WriteString("_value_")
		b.WriteString(s.Value)

		indexes = append(indexes, b.String())
	}

	return indexes
}

func buildSelectorMatchExactIndex(selectors []*datastorev1.Selector) string {
	b := strings.Builder{}
	b.WriteString(selectorMatchPrefix)
	b.WriteString(matcherExactInfix)

	for i, s := range selectors {
		if i > 0 {
			b.WriteString("__")
		}
		b.WriteString("type_")
		b.WriteString(s.Type)
		b.WriteString("_value_")
		b.WriteString(s.Value)
	}

	return b.String()
}

func buildSelectorSupersetMatchIndexes(selectors []*datastorev1.Selector) []string {
	powerset := powerSlice(selectors)

	indexes := make([]string, 0, len(selectors))

	for _, subset := range powerset {
		b := strings.Builder{}
		b.WriteString(selectorMatchPrefix)
		b.WriteString(matcherSupersetInfix)

		for i, sub := range subset {
			if i > 0 {
				b.WriteString("__")
			}
			b.WriteString("type_")
			b.WriteString(sub.Type)
			b.WriteString("_value_")
			b.WriteString(sub.Value)
		}

		indexes = append(indexes, b.String())
	}

	return indexes
}
