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
		domainKey, err := toDomainKey(domain)
		if err != nil {
			return nil, err
		}
		allowlist[domainKey] = struct{}{}
	}
	return func(domain string) error {
		domainKey, err := toDomainKey(domain)
		if err != nil {
			return err
		}
		if _, allowed := allowlist[domainKey]; !allowed {
			return fmt.Errorf("domain %q is not allowed", domain)
		}
		return nil
	}, nil
}

// AllowAnyDomain returns a policy that allows any domain
func AllowAnyDomain() DomainPolicy {
	return func(domain string) error {
		_, err := toDomainKey(domain)
		return err
	}
}

func toDomainKey(domain string) (string, error) {
	punycode, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("domain %q is not a valid domain name: %w", domain, err)
	}
	if punycode != domain {
		return "", fmt.Errorf("domain %q must already be punycode encoded", domain)
	}
	return domain, nil
}
