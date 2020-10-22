package entry

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/types"
)

// parseSelector parses a CLI string from type:value into a selector type.
// Everything to the right of the first ":" is considered a selector value.
func parseSelector(str string) (*types.Selector, error) {
	parts := strings.SplitAfterN(str, ":", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("selector \"%s\" must be formatted as type:value", str)
	}

	s := &types.Selector{
		// Strip the trailing delimiter
		Type:  strings.TrimSuffix(parts[0], ":"),
		Value: parts[1],
	}
	return s, nil
}

func printEntry(e *types.Entry) {
	fmt.Printf("Entry ID      : %s\n", e.Id)
	fmt.Printf("SPIFFE ID     : %s\n", protoToIDString(e.SpiffeId))
	fmt.Printf("Parent ID     : %s\n", protoToIDString(e.ParentId))
	fmt.Printf("Revision      : %d\n", e.RevisionNumber)

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

func parseFile(path string) ([]*types.Entry, error) {
	dat, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	commonEntries := &common.RegistrationEntries{}
	if err := json.Unmarshal(dat, &commonEntries); err != nil {
		return nil, err
	}

	return api.RegistrationEntriesToProto(commonEntries.Entries)
}

func idStringToProto(id string) (*types.SPIFFEID, error) {
	idType, err := spiffeid.FromString(id)
	if err != nil {
		return nil, err
	}
	return &types.SPIFFEID{
		TrustDomain: idType.TrustDomain().String(),
		Path:        idType.Path(),
	}, nil
}

// protoToIDString converts a SPIFFE ID from the given *types.SPIFFEID to string
func protoToIDString(id *types.SPIFFEID) string {
	return fmt.Sprintf("spiffe://%s%s", id.TrustDomain, id.Path)
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
