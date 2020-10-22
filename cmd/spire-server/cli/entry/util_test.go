package entry

import (
	"bytes"
	"io/ioutil"
	"path"
	"testing"

	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasSelectors(t *testing.T) {
	selectors := []*common.Selector{
		{Type: "foo", Value: "bar"},
		{Type: "bar", Value: "bat"},
		{Type: "bat", Value: "baz"},
	}

	entry := &common.RegistrationEntry{
		ParentId:  "spiffe://example.org/foo",
		SpiffeId:  "spiffe://example.org/bar",
		Selectors: selectors,
	}

	a := assert.New(t)
	a.True(hasSelectors(entry, selectorToFlag(t, selectors[0:1])))
	a.True(hasSelectors(entry, selectorToFlag(t, selectors[2:3])))
	a.True(hasSelectors(entry, selectorToFlag(t, selectors[1:3])))

	newSelectors := []*common.Selector{
		{Type: "bar", Value: "foo"},
		{Type: "bat", Value: "bar"},
	}
	selectors = append(selectors, newSelectors...)

	a.False(hasSelectors(entry, selectorToFlag(t, selectors[3:4])))
	a.False(hasSelectors(entry, selectorToFlag(t, selectors[2:4])))
}

func selectorToFlag(t *testing.T, selectors []*common.Selector) StringsFlag {
	resp := StringsFlag{}
	for _, s := range selectors {
		str := s.Type + ":" + s.Value
		require.NoError(t, resp.Set(str))
	}

	return resp
}

func TestParseEntryJSON(t *testing.T) {
	testCases := []struct {
		name         string
		testDataPath string
		in           *bytes.Buffer
		wantErr      bool
	}{
		{
			name:         "Parse valid JSON",
			testDataPath: path.Join(util.ProjectRoot(), "test/fixture/registration/good.json"),
		},
		{
			name:         "Parse valid JSON from STDIN",
			testDataPath: path.Join(util.ProjectRoot(), "test/fixture/registration/good.json"),
			in:           new(bytes.Buffer),
		},
		{
			name:         "Parse invalid JSON",
			testDataPath: "test/fixture/registration/invalid_json.json",
			wantErr:      true,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			p := testCase.testDataPath

			if testCase.in != nil {
				data, err := ioutil.ReadFile(testCase.testDataPath)
				assert.NoError(t, err)
				_, err = testCase.in.Write(data)
				assert.NoError(t, err)
				p = "-"
			}

			entries, err := parseEntryJSON(testCase.in, p)
			if testCase.wantErr {
				require.Error(t, err)
				return
			}
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
		})
	}
}
