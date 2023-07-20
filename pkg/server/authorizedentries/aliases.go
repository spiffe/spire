package authorizedentries

type aliasRecord struct {
	EntryID      string
	AliasID      string
	Selector     Selector
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
