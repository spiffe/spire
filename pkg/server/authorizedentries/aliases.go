package authorizedentries

type aliasRecord struct {
	// EntryID is the ID of the registration entry that defines this node
	// alias.
	EntryID string

	// AliasID is the SPIFFE ID of nodes that match this alias.
	AliasID string

	// Selector is the specific selector we use to fan out to this record
	// during the crawl.
	Selector Selector

	// AllSelectors is here out of convenience to verify that the agent
	// possesses a superset of the alias's selectors and is therefore
	// authorized for the alias.
	AllSelectors selectorSet
}

func aliasRecordByEntryID(a, b aliasRecord) bool {
	switch {
	case a.EntryID < b.EntryID:
		return true
	case a.EntryID > b.EntryID:
		return false
	case a.Selector.Type < b.Selector.Type:
		return true
	case a.Selector.Type > b.Selector.Type:
		return false
	default:
		return a.Selector.Value < b.Selector.Value
	}
}

func aliasRecordBySelector(a, b aliasRecord) bool {
	switch {
	case a.Selector.Type < b.Selector.Type:
		return true
	case a.Selector.Type > b.Selector.Type:
		return false
	case a.Selector.Value < b.Selector.Value:
		return true
	case a.Selector.Value > b.Selector.Value:
		return false
	default:
		return a.EntryID < b.EntryID
	}
}
