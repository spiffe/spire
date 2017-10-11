package command

import (
	"path"
	"testing"

	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO: Test additional scenarios
func TestRegisterParseConfig(t *testing.T) {
	c := &RegisterConfig{
		Addr:      defaultServerAddr,
		ParentID:  "spiffe://example.org/foo",
		SpiffeID:  "spiffe://example.org/bar",
		Ttl:       60,
		Selectors: SelectorFlag{"unix:uid:1000", "unix:gid:1000"},
	}

	entries, err := Register{}.parseConfig(c)
	require.NoError(t, err)

	expectedEntry := &common.RegistrationEntry{
		ParentId: "spiffe://example.org/foo",
		SpiffeId: "spiffe://example.org/bar",
		Ttl:      60,
		Selectors: []*common.Selector{
			&common.Selector{Type: "unix", Value: "uid:1000"},
			&common.Selector{Type: "unix", Value: "gid:1000"},
		},
	}

	expectedEntries := []*common.RegistrationEntry{expectedEntry}
	assert.Equal(t, expectedEntries, entries)
}

func TestRegisterParseFile(t *testing.T) {
	p := path.Join(util.ProjectRoot(), "test/fixture/registration/good.json")
	entries, err := Register{}.parseFile(p)
	require.NoError(t, err)

	entry1 := &common.RegistrationEntry{
		Selectors: []*common.Selector{
			&common.Selector{
				Type:  "unix",
				Value: "uid:1111",
			},
		},
		SpiffeId: "spiffe://example.org/Blog",
		ParentId: "spiffe://example.org/spire/agent/join_token/TokenBlog",
		Ttl:      200,
	}
	entry2 := &common.RegistrationEntry{
		Selectors: []*common.Selector{
			&common.Selector{
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

func TestRegisterParseSelector(t *testing.T) {
	str := "unix:uid:1000"
	s, err := Register{}.parseSelector(str)
	require.NoError(t, err)
	assert.Equal(t, "unix", s.Type)
	assert.Equal(t, "uid:1000", s.Value)

	str = "unix"
	_, err = Register{}.parseSelector(str)
	assert.NotNil(t, err)
}
