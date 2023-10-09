package authorizedentries

type agentRecord struct {
	ID string

	// ExpiresAt is seconds since unix epoch. Using intead of time.Time for
	// reduced memory usage and better cache locality.
	ExpiresAt int64

	Selectors selectorSet
}

func agentRecordByID(a, b agentRecord) bool {
	return a.ID < b.ID
}

func agentRecordByExpiresAt(a, b agentRecord) bool {
	switch {
	case a.ExpiresAt < b.ExpiresAt:
		return true
	case a.ExpiresAt > b.ExpiresAt:
		return false
	default:
		return a.ID < b.ID
	}
}
