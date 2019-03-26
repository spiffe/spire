package entry

import (
	"path"
	"testing"

	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmdutil "github.com/spiffe/spire/cmd/spire-server/util"
)

// TODO: Test additional scenarios

// also tests that ordering is preserved in Selectors and Federates
// rather than sorted in some way
func TestUpdateCLI(t *testing.T) {
	updatedConfig, err := UpdateCLI{}.newConfig([]string{
		"-parentID", "spiffe://example.org/foo",
		"-spiffeID", "spiffe://example.org/bar",
		"-ttl", "60",
		"-selector", "unix:uid:1000",
		"-selector", "unix:gid:1000",
		"-selector", "alpha:alpha:2000",
		"-selector", "zebra:zebra:2000",
		"-federatesWith", "spiffe://domainA.test",
		"-federatesWith", "spiffe://domain1.test",
		"-federatesWith", "spiffe://domain2.test",
		"-federatesWith", "spiffe://domainB.test",
		"-admin",
		"-entryExpiry", "1552410266",
	})
	require.NoError(t, err)

	c := &UpdateConfig{
		RegistrationUDSPath: cmdutil.DefaultSocketPath,
		ParentID:            "spiffe://example.org/foo",
		SpiffeID:            "spiffe://example.org/bar",
		Ttl:                 60,
		Selectors:           StringsFlag{"unix:uid:1000", "unix:gid:1000", "alpha:alpha:2000", "zebra:zebra:2000"},
		FederatesWith:       StringsFlag{"spiffe://domainA.test", "spiffe://domain1.test", "spiffe://domain2.test", "spiffe://domainB.test"},
		Admin:               true,
		EntryExpiry:         1552410266,
	}

	assert.Equal(t, updatedConfig, c)
}

func TestUpdateParseConfig(t *testing.T) {
	c := &UpdateConfig{
		RegistrationUDSPath: cmdutil.DefaultSocketPath,
		ParentID:            "spiffe://example.org/foo",
		SpiffeID:            "spiffe://example.org/bar",
		Ttl:                 60,
		Selectors:           StringsFlag{"unix:uid:1000", "unix:gid:1000"},
		FederatesWith:       StringsFlag{"spiffe://domain1.test", "spiffe://domain2.test"},
		Admin:               true,
		EntryExpiry:         1552410266,
	}

	entries, err := UpdateCLI{}.parseConfig(c)
	require.NoError(t, err)

	expectedEntry := &common.RegistrationEntry{
		ParentId: "spiffe://example.org/foo",
		SpiffeId: "spiffe://example.org/bar",
		Ttl:      60,
		Selectors: []*common.Selector{
			{Type: "unix", Value: "uid:1000"},
			{Type: "unix", Value: "gid:1000"},
		},
		FederatesWith: []string{
			"spiffe://domain1.test",
			"spiffe://domain2.test",
		},
		Admin:       true,
		EntryExpiry: 1552410266,
	}

	expectedEntries := []*common.RegistrationEntry{expectedEntry}
	assert.Equal(t, expectedEntries, entries)
}

func TestUpdateParseFile(t *testing.T) {
	p := path.Join(util.ProjectRoot(), "test/fixture/registration/good.json")
	entries, err := UpdateCLI{}.parseFile(p)
	require.NoError(t, err)

	entry1 := &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{
				Type:  "unix",
				Value: "uid:1111",
			},
		},
		SpiffeId: "spiffe://example.org/Blog",
		ParentId: "spiffe://example.org/spire/agent/join_token/TokenBlog",
		Ttl:      200,
		Admin:    true,
	}
	entry2 := &common.RegistrationEntry{
		Selectors: []*common.Selector{
			{
				Type:  "unix",
				Value: "uid:1111",
			},
		},
		SpiffeId: "spiffe://example.org/Database",
		ParentId: "spiffe://example.org/spire/agent/join_token/TokenDatabase",
		Ttl:      200,
	}

	expectedEntries := []*common.RegistrationEntry{
		entry1,
		entry2,
	}
	assert.Equal(t, expectedEntries, entries)
}
