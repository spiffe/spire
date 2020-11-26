package entry

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
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

func printEntry(e *types.Entry, env *common_cli.Env) {
	env.Printf("Entry ID         : %s\n", e.Id)
	env.Printf("SPIFFE ID        : %s\n", protoToIDString(e.SpiffeId))
	env.Printf("Parent ID        : %s\n", protoToIDString(e.ParentId))
	env.Printf("Revision         : %d\n", e.RevisionNumber)

	if e.Downstream {
		env.Printf("Downstream       : %t\n", e.Downstream)
	}

	if e.Ttl == 0 {
		env.Printf("TTL              : default\n")
	} else {
		env.Printf("TTL              : %d\n", e.Ttl)
	}

	if e.ExpiresAt != 0 {
		env.Printf("Expiration time  : %s\n", time.Unix(e.ExpiresAt, 0).UTC())
	}

	for _, s := range e.Selectors {
		env.Printf("Selector         : %s:%s\n", s.Type, s.Value)
	}
	for _, id := range e.FederatesWith {
		env.Printf("FederatesWith    : %s\n", id)
	}
	for _, dnsName := range e.DnsNames {
		env.Printf("DNS name         : %s\n", dnsName)
	}

	// admin is rare, so only show admin if true to keep
	// from muddying the output.
	if e.Admin {
		env.Printf("Admin            : %t\n", e.Admin)
	}

	env.Println()
}

// idStringToProto converts a SPIFFE ID from the given string to *types.SPIFFEID
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
	if id == nil {
		return ""
	}
	return fmt.Sprintf("spiffe://%s%s", id.TrustDomain, id.Path)
}

// parseFile parses JSON represented RegistrationEntries
// if path is "-" read JSON from STDIN
func parseFile(path string) ([]*types.Entry, error) {
	return parseEntryJSON(os.Stdin, path)
}

func parseEntryJSON(in io.Reader, path string) ([]*types.Entry, error) {
	entries := &common.RegistrationEntries{}

	r := in
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}

	dat, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(dat, &entries); err != nil {
		return nil, err
	}
	return api.RegistrationEntriesToProto(entries.Entries)
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
