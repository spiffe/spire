package x509util

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var isDNSLabel = regexp.MustCompile(`^[a-zA-Z0-9]([-]*[a-zA-Z0-9])+$`).MatchString

// ValidateDNS validates that provided string is a valid DNS name
func ValidateDNS(dns string) error {
	// follow https://tools.ietf.org/html/rfc5280#section-4.2.1.6
	// do not allow empty or the technically valid DNS " "
	dns = strings.TrimSpace(dns)
	if len(dns) == 0 {
		return errors.New("empty or only whitespace")
	}

	// handle up to 255 characters
	if len(dns) > 255 {
		return errors.New("length exceeded")
	}

	// a DNS is split into labels by "."
	splitDNS := strings.Split(dns, ".")
	for _, label := range splitDNS {
		if err := validateDNSLabel(label); err != nil {
			return err
		}
	}

	return nil
}

func validateDNSLabel(label string) error {
	// follow https://tools.ietf.org/html/rfc5280#section-4.2.1.6 guidance
	// <label> ::= <let-dig> [ [ <ldh-str> ] <let-dig> ]
	// <ldh-str> ::= <let-dig-hyp> | <let-dig-hyp> <ldh-str>
	switch {
	case len(label) == 0:
		return errors.New("label is empty")
	case len(label) > 63:
		return fmt.Errorf("label length exceeded: %v", label)
	case !isDNSLabel(label):
		return fmt.Errorf("label does not match regex: %v", label)
	}

	return nil
}
