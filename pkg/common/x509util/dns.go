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
	ErrEmptyDomain              = errors.New("empty domain")
	ErrIDNAError                = errors.New("idna error")
	ErrDomainEndsWithDot        = errors.New("domain ends with dot")
	ErrWildcardOverlap          = errors.New("wildcard overlap")
	ErrNameMustBeAscii          = errors.New("name must be ascii")
	errNoWildcardAllowed        = errors.New("wildcard not allowed")
)

func ValidateAndNormalize(domain string) (string, error) {
	if !utf8string.NewString(domain).IsASCII() {
		return "", ErrNameMustBeAscii
	}

	starCount := strings.Count(domain, "*")
	if starCount <= 0 {
		return validNonwildcardLabel(domain)
	}

	if starCount > 1 {
		return "", ErrTooManyWildcards
	}

	if !strings.HasPrefix(domain, "*.") {
		return "", ErrWildcardMustBeFirstLabel
	}

	domain = strings.TrimPrefix(domain, "*.")
	validated, err := validNonwildcardLabel(domain)
	if err != nil {
		return "", err
	}

	return "*." + validated, nil
}

func validNonwildcardLabel(domain string) (string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return "", ErrEmptyDomain
	}

	if strings.HasSuffix(domain, ".") {
		return "", ErrDomainEndsWithDot
	}

	if strings.HasPrefix(domain, "*.") {
		return "", errNoWildcardAllowed
	}

	profile := idna.New(
		idna.StrictDomainName(true),
		idna.ValidateLabels(true),
		idna.VerifyDNSLength(true),
		idna.CheckJoiners(true),
		idna.BidiRule(),
		idna.CheckHyphens(true),
	)

	checked, err := profile.ToASCII(domain)
	if err != nil {
		return "", errors.Join(ErrIDNAError, err)
	}

	return checked, nil
}

func WildcardOverlap(names []string) error {
	nm := map[string]struct{}{}

	for _, name := range names {
		nm[name] = struct{}{}
	}

	for name := range nm {
		// While we're checking, we don't need to care about wildcards
		if strings.HasPrefix(name, "*") {
			continue
		}

		// Let's split this non-wildcard DNS name into its corresponding labels
		labels := strings.Split(name, ".")
		labels[0] = "*" // Let's now replace the first label with a wildcard
		if _, ok := nm[strings.Join(labels, ".")]; ok {
			return fmt.Errorf("name %q overlaps with an existing wildcard name in the list: %w", name, ErrWildcardOverlap)
		}
	}

	return nil
}
