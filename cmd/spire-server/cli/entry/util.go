package entry

// parseSelector parses a CLI string from type:value into a selector type.
// Everything to the right of the first ":" is considered a selector value.
func parseSelector(str string) (*common.Selector, error) {
	parts := strings.SplitAfterN(str, ":", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("selector \"%s\" must be formatted as type:value", str)
	}

	s := &common.Selector{
		// Strip the trailing delimiter
		Type:  strings.TrimSuffix(parts[0], ":"),
		Value: parts[1],
	}
	return s, nil
}

func printEntry(e *common.RegistrationEntry, id string) {
	if id != "" {
		fmt.Printf("Entry ID:\t%s\n", id)
	}
	fmt.Printf("SPIFFE ID:\t%s\n", e.SpiffeId)
	fmt.Printf("Parent ID:\t%s\n", e.ParentId)
	fmt.Printf("TTL:\t\t%v\n", e.Ttl)

	for _, s := range e.Selectors {
		fmt.Printf("Selector:\t%s:%s\n", s.Type, s.Value)
	}

	fmt.Println()
}

// Define a custom type for selectors. Doing
// this allows us to support repeatable flags
type SelectorFlag []string

func (s *SelectorFlag) String() string {
	return fmt.Sprint(*s)
}

func (s *SelectorFlag) Set(val string) error {
	*s = append(*s, val)
	return nil
}
