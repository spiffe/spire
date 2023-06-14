package entry

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/proto/spire/common"
)

func printEntry(e *types.Entry, printf func(string, ...interface{}) error) {
	_ = printf("Entry ID         : %s\n", printableEntryID(e.Id))
	_ = printf("SPIFFE ID        : %s\n", protoToIDString(e.SpiffeId))
	_ = printf("Parent ID        : %s\n", protoToIDString(e.ParentId))
	_ = printf("Revision         : %d\n", e.RevisionNumber)

	if e.Downstream {
		_ = printf("Downstream       : %t\n", e.Downstream)
	}

	if e.X509SvidTtl == 0 {
		_ = printf("X509-SVID TTL    : default\n")
	} else {
		_ = printf("X509-SVID TTL    : %d\n", e.X509SvidTtl)
	}

	if e.JwtSvidTtl == 0 {
		_ = printf("JWT-SVID TTL     : default\n")
	} else {
		_ = printf("JWT-SVID TTL     : %d\n", e.JwtSvidTtl)
	}

	if e.ExpiresAt != 0 {
		_ = printf("Expiration time  : %s\n", time.Unix(e.ExpiresAt, 0).UTC())
	}

	for _, s := range e.Selectors {
		_ = printf("Selector         : %s:%s\n", s.Type, s.Value)
	}
	for _, id := range e.FederatesWith {
		_ = printf("FederatesWith    : %s\n", id)
	}
	for _, dnsName := range e.DnsNames {
		_ = printf("DNS name         : %s\n", dnsName)
	}

	// admin is rare, so only show admin if true to keep
	// from muddying the output.
	if e.Admin {
		_ = printf("Admin            : %t\n", e.Admin)
	}

	if e.StoreSvid {
		_ = printf("StoreSvid        : %t\n", e.StoreSvid)
	}

	if e.Hint != "" {
		_ = printf("Hint             : %s\n", e.Hint)
	}

	_ = printf("\n")
}

// idStringToProto converts a SPIFFE ID from the given string to *types.SPIFFEID
func idStringToProto(id string) (*types.SPIFFEID, error) {
	idType, err := spiffeid.FromString(id)
	if err != nil {
		return nil, err
	}
	return &types.SPIFFEID{
		TrustDomain: idType.TrustDomain().Name(),
		Path:        idType.Path(),
	}, nil
}

func printableEntryID(id string) string {
	if id == "" {
		return "(none)"
	}
	return id
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

	dat, err := io.ReadAll(r)
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

// String returns the string flag.
func (s *StringsFlag) String() string {
	return fmt.Sprint(*s)
}

// Set appends the string flag.
func (s *StringsFlag) Set(val string) error {
	*s = append(*s, val)
	return nil
}
