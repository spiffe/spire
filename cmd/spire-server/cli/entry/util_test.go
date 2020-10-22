package entry

import (
	"bytes"
	"io/ioutil"
	"path"
	"testing"

	"github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIDStringToProto(t *testing.T) {
	id, err := idStringToProto("spiffe://example.org/host")
	require.NoError(t, err)
	require.Equal(t, types.SPIFFEID{TrustDomain: "example.org", Path: "/host"}, *id)

	id, err = idStringToProto("example.org/host")
	require.Error(t, err)
	require.Nil(t, id)
}

func TestProtoToIDString(t *testing.T) {
	id := protoToIDString(&types.SPIFFEID{TrustDomain: "example.org", Path: "/host"})
	require.Equal(t, "spiffe://example.org/host", id)
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

			entry1 := &types.Entry{
				Selectors: []*types.Selector{
					{
						Type:  "unix",
						Value: "uid:1111",
					},
				},
				SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/Blog"},
				ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenBlog"},
				Ttl:      200,
				Admin:    true,
			}
			entry2 := &types.Entry{
				Selectors: []*types.Selector{
					{
						Type:  "unix",
						Value: "uid:1111",
					},
				},
				SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/Database"},
				ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenDatabase"},
				Ttl:      200,
			}

			expectedEntries := []*types.Entry{
				entry1,
				entry2,
			}
			spiretest.RequireProtoListEqual(t, expectedEntries, entries)
		})
	}
}
