package x509util

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/exp/utf8string"
	"golang.org/x/net/idna"
)

var (
	ErrTooManyWildcards         = errors.New("too many wildcards")
	ErrWildcardMustBeFirstLabel = errors.New("wildcard must be first label")
	ErrEmptyDomain              = errors.New("empty or only whitespace")
	ErrIDNAError                = errors.New("idna error")
	ErrDomainEndsWithDot        = errors.New("domain ends with dot")
	ErrWildcardOverlap          = errors.New("wildcard overlap")
	ErrNameMustBeASCII          = errors.New("name must be ascii")
	ErrLabelMismatchAfterIDNA   = errors.New("label mismatch after idna")
	errNoWildcardAllowed        = errors.New("wildcard not allowed")
)

func ValidateLabel(domain string) error {
	if !utf8string.NewString(domain).IsASCII() {
		return ErrNameMustBeASCII
	}

	starCount := strings.Count(domain, "*")
	if starCount <= 0 {
		return validNonwildcardLabel(domain)
	}

	if starCount > 1 {
		return ErrTooManyWildcards
	}

	domain, hadPrefix := strings.CutPrefix(domain, "*.")

	if !hadPrefix {
		return ErrWildcardMustBeFirstLabel
	}

	return validNonwildcardLabel(domain)
}

func validNonwildcardLabel(domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ErrEmptyDomain
	}

	if strings.HasSuffix(domain, ".") {
		return ErrDomainEndsWithDot
	}

	if strings.HasPrefix(domain, "*.") {
		return errNoWildcardAllowed
	}

	// DNS names are case insensitive (RFC 4343), IDNA validation is not.
	domain = strings.ToLower(domain)

	// STD3 rules would reject characters that are common in practice, e.g.
	// underscores.
	profile := idna.New(
		idna.StrictDomainName(false),
		idna.ValidateLabels(true),
		idna.VerifyDNSLength(true),
		idna.CheckJoiners(true),
		idna.BidiRule(),
		idna.CheckHyphens(true),
	)

	checked, err := profile.ToASCII(domain)
	if err != nil {
		return errors.Join(ErrIDNAError, err)
	}

	// Defensive check.
	if domain != checked {
		return fmt.Errorf("input domain name %q does not match idna output %q: %w", domain, checked, ErrLabelMismatchAfterIDNA)
	}

	return nil
}

func CheckForWildcardOverlap(names []string) error {
	nm := map[string]struct{}{}

	// DNS names are case insensitive (RFC 4343), compare them folded.
	for _, name := range names {
		nm[strings.ToLower(name)] = struct{}{}
	}

	for _, name := range names {
		folded := strings.ToLower(name)

		// While we're checking, we don't need to care about wildcards
		if strings.HasPrefix(folded, "*") {
			continue
		}

		// Let's split this non-wildcard DNS name into its corresponding labels
		labels := strings.Split(folded, ".")
		labels[0] = "*" // Let's now replace the first label with a wildcard
		if _, ok := nm[strings.Join(labels, ".")]; ok {
			return fmt.Errorf("name %q overlaps with an existing wildcard name in the list: %w", name, ErrWildcardOverlap)
		}
	}

	return nil
}
