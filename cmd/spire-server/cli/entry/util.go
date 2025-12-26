package entry

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/proto/spire/common"
)

func printEntry(e *types.Entry, printf func(string, ...any) error) {
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

	// Only show JWT-SVID audience policies if configured
	if e.JwtSvidDefaultAudiencePolicy != types.JWTSVIDAudiencePolicy_JWT_SVID_AUDIENCE_POLICY_DEFAULT {
		_ = printf("JWT Default Policy: %s\n", jwtSVIDAudiencePolicyName(e.JwtSvidDefaultAudiencePolicy))
	}
	if len(e.JwtSvidAudiencePolicies) > 0 {
		// Sort audiences for consistent output
		audiences := make([]string, 0, len(e.JwtSvidAudiencePolicies))
		for aud := range e.JwtSvidAudiencePolicies {
			audiences = append(audiences, aud)
		}
		sort.Strings(audiences)
		for _, aud := range audiences {
			policy := e.JwtSvidAudiencePolicies[aud]
			_ = printf("JWT Aud Policy   : %s:%s\n", aud, jwtSVIDAudiencePolicyName(policy))
		}
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

// AudiencePolicyFlag defines a custom type for audience:policy pairs.
// Format: "audience:policy" where policy is one of: default, auditable, unique
type AudiencePolicyFlag map[string]types.JWTSVIDAudiencePolicy

// String returns the string representation of the flag.
func (a *AudiencePolicyFlag) String() string {
	return fmt.Sprint(*a)
}

// Set parses and appends an audience:policy pair.
func (a *AudiencePolicyFlag) Set(val string) error {
	parts := strings.SplitN(val, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid audience policy format %q, expected audience:policy", val)
	}

	audience := parts[0]
	if audience == "" {
		return fmt.Errorf("audience cannot be empty in %q", val)
	}

	policy, err := parseJWTSVIDAudiencePolicy(parts[1])
	if err != nil {
		return err
	}

	if *a == nil {
		*a = make(map[string]types.JWTSVIDAudiencePolicy)
	}
	(*a)[audience] = policy
	return nil
}

// parseJWTSVIDAudiencePolicy parses a policy string into the enum value.
func parseJWTSVIDAudiencePolicy(s string) (types.JWTSVIDAudiencePolicy, error) {
	switch strings.ToLower(s) {
	case "default", "":
		return types.JWTSVIDAudiencePolicy_JWT_SVID_AUDIENCE_POLICY_DEFAULT, nil
	case "auditable":
		return types.JWTSVIDAudiencePolicy_JWT_SVID_AUDIENCE_POLICY_AUDITABLE, nil
	case "unique":
		return types.JWTSVIDAudiencePolicy_JWT_SVID_AUDIENCE_POLICY_UNIQUE, nil
	default:
		return types.JWTSVIDAudiencePolicy_JWT_SVID_AUDIENCE_POLICY_DEFAULT,
			fmt.Errorf("invalid JWT-SVID audience policy %q, must be one of: default, auditable, unique", s)
	}
}

// jwtSVIDAudiencePolicyName returns the human-readable name of the policy.
func jwtSVIDAudiencePolicyName(p types.JWTSVIDAudiencePolicy) string {
	switch p {
	case types.JWTSVIDAudiencePolicy_JWT_SVID_AUDIENCE_POLICY_AUDITABLE:
		return "auditable"
	case types.JWTSVIDAudiencePolicy_JWT_SVID_AUDIENCE_POLICY_UNIQUE:
		return "unique"
	default:
		return "default"
	}
}
