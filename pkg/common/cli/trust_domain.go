package cli

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// maxTrustDomainLength is the maximum length of a trust domain according
// to the SPIFFE standard.
const maxTrustDomainLength = 255

// ParseTrustDomain parses a configured trustDomain in a consistent way
// for either the SPIRE agent or server.
func ParseTrustDomain(trustDomain string, logger logrus.FieldLogger) (td spiffeid.TrustDomain, err error) {
	// Warn on a non-conforming trust domain to avoid breaking backwards compatibility
	if len(trustDomain) > maxTrustDomainLength {
		logger.WithField("trust_domain", trustDomain).
			Warnf("Configured trust domain name should be less than %d characters to be SPIFFE compliant; "+
				"a longer trust domain name may impact interoperability",
				maxTrustDomainLength)
	}

	td, err = spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return td, fmt.Errorf("could not parse trust_domain %q: %v", trustDomain, err)
	}
	return
}
