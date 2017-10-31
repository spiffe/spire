package registration

import (
	"github.com/spiffe/spire/proto/common"
)

func GetRegistrationEntries() []*common.RegistrationEntry {
	blogEntry := &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/Blog",
		ParentId: "spiffe://example.org/spire/agent/join_token/TokenBlog",
		Selectors: []*common.Selector{
			{Type: "unix", Value: "uid:111"},
		},
		Ttl: 200,
	}
	databaseEntry := &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/Database",
		ParentId: "spiffe://example.org/spire/agent/join_token/TokenDatabase",
		Selectors: []*common.Selector{
			{Type: "unix", Value: "uid:111"},
		},
		Ttl: 200,
	}

	return []*common.RegistrationEntry{blogEntry, databaseEntry}
}
