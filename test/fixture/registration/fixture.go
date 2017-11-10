package registration

import (
	"encoding/json"
	"io/ioutil"
	"path"

	"github.com/spiffe/spire/proto/common"
	testutil "github.com/spiffe/spire/test/util"
)

func GetRegistrationEntries() []*common.RegistrationEntry {
	blogEntry := &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/Blog",
		ParentId: "spiffe://example.org/spire/agent/join_token/TokenBlog",
		Selectors: []*common.Selector{
			&common.Selector{Type: "unix", Value: "uid:111"},
		},
		Ttl: 200,
	}
	databaseEntry := &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/Database",
		ParentId: "spiffe://example.org/spire/agent/join_token/TokenDatabase",
		Selectors: []*common.Selector{
			&common.Selector{Type: "unix", Value: "uid:111"},
		},
		Ttl: 200,
	}

	return []*common.RegistrationEntry{blogEntry, databaseEntry}
}

func FromFile(fileName string) []*common.RegistrationEntry {
	regEntries := &common.RegistrationEntries{}
	path := path.Join(testutil.ProjectRoot(), "test/fixture/registration/", fileName)
	dat, _ := ioutil.ReadFile(path)
	json.Unmarshal(dat, &regEntries)
	return regEntries.Entries
}
