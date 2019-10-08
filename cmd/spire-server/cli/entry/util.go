package entry

import (
	"fmt"
	"strings"

	"github.com/spiffe/spire/proto/spire/common"
)

// hasSelectors takes a registration entry and a selector flag set. It returns
// true if the registration entry possesses all selectors in the set. An error
// is returned if we run into trouble parsing the selector flags.
func hasSelectors(entry *common.RegistrationEntry, flags StringsFlag) (bool, error) {
	for _, f := range flags {
		selector, err := parseSelector(f)
		if err != nil {
			return false, err
		}

		if !hasSelector(entry, selector) {
			return false, nil
		}
	}

	return true, nil
}

// hasSelector returns true if the given registration entry includes the
// selector in question.
func hasSelector(entry *common.RegistrationEntry, selector *common.Selector) bool {
	var found bool

	for _, s := range entry.Selectors {
		if s.Type == selector.Type && s.Value == selector.Value {
			found = true
			break
		}
	}

	return found
}

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

func printEntry(e *common.RegistrationEntry) {
	fmt.Printf("Entry ID      : %s\n", e.EntryId)
	fmt.Printf("SPIFFE ID     : %s\n", e.SpiffeId)
	fmt.Printf("Parent ID     : %s\n", e.ParentId)

	if e.Downstream {
		fmt.Printf("Downstream    : %t\n", e.Downstream)
	}

	if e.Ttl == 0 {
		fmt.Printf("TTL           : default\n")
	} else {
		fmt.Printf("TTL           : %d\n", e.Ttl)
	}

	for _, s := range e.Selectors {
		fmt.Printf("Selector      : %s:%s\n", s.Type, s.Value)
	}
	for _, id := range e.FederatesWith {
		fmt.Printf("FederatesWith : %s\n", id)
	}
	for _, dnsName := range e.DnsNames {
		fmt.Printf("DNS name      : %s\n", dnsName)
	}

	// admin is rare, so only show admin if true to keep
	// from muddying the output.
	if e.Admin {
		fmt.Printf("Admin         : %t\n", e.Admin)
	}

	fmt.Println()
}

// StringsFlag defines a custom type for string lists. Doing
// this allows us to support repeatable string flags.
type StringsFlag []string

func (s *StringsFlag) String() string {
	return fmt.Sprint(*s)
}

func (s *StringsFlag) Set(val string) error {
	*s = append(*s, val)
	return nil
}
