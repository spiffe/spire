package main

import (
	"fmt"

	"golang.org/x/net/idna"
)

type DomainPolicy = func(domain string) error

// DomainAllowlist returns a policy that allows any domain in the given domains
func DomainAllowlist(domains ...string) (DomainPolicy, error) {
	allowlist := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		domain, err := idna.Lookup.ToASCII(domain)
		if err != nil {
			return nil, fmt.Errorf("domain %q is not a valid domain name: %v", domain, err)
		}
		allowlist[domain] = struct{}{}
	}
	return func(domain string) error {
		domain, err := idna.Lookup.ToASCII(domain)
		if err != nil {
			return fmt.Errorf("domain %q is not a valid domain name: %v", domain, err)
		}
		if _, allowed := allowlist[domain]; !allowed {
			return fmt.Errorf("domain %q is not allowed", domain)
		}
		return nil
	}, nil
}

// AllowAnyDomain returns a policy that allows any domain
func AllowAnyDomain() DomainPolicy {
	return func(domain string) error {
		return nil
	}
}
