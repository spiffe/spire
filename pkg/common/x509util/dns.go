package x509util

import (
	"errors"
	"strings"

	"golang.org/x/net/idna"
)

var (
	ErrTooManyWildcards         = errors.New("too many wildcards")
	ErrWildcardMustBeFirstLabel = errors.New("wildcard must be first label")
	ErrEmptyDomain              = errors.New("empty domain")
	ErrIDNAError                = errors.New("idna error")
	ErrDomainEndsWithDot        = errors.New("domain ends with dot")
	errNoWildcardAllowed        = errors.New("wildcard not allowed")
)

func ValidateAndNormalize(domain string) (string, error) {
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
		idna.BidiRule(),
		idna.CheckJoiners(true),
		idna.CheckHyphens(true),
	)

	checked, err := profile.ToASCII(domain)
	if err != nil {
		return "", errors.Join(ErrIDNAError, err)
	}
	return checked, nil
}
