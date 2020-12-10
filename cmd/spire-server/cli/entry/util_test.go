package entry

import (
	"bytes"
	"io/ioutil"
	"path"
	"testing"

	"github.com/mitchellh/cli"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

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

func TestProtoToIDString(t *testing.T) {
	id := protoToIDString(&types.SPIFFEID{TrustDomain: "example.org", Path: "/host"})
	require.Equal(t, "spiffe://example.org/host", id)

	id = protoToIDString(nil)
	require.Empty(t, id)
}

func TestIDStringToProto(t *testing.T) {
	id, err := idStringToProto("spiffe://example.org/host")
	require.NoError(t, err)
	require.Equal(t, &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"}, id)

	id, err = idStringToProto("example.org/host")
	require.Error(t, err)
	require.Nil(t, id)
}

type entryTest struct {
	stdin  *bytes.Buffer
	stdout *bytes.Buffer
	stderr *bytes.Buffer

	args   []string
	server *fakeEntryServer

	client cli.Command
}

func (e *entryTest) afterTest(t *testing.T) {
	t.Logf("TEST:%s", t.Name())
	t.Logf("STDOUT:\n%s", e.stdout.String())
	t.Logf("STDIN:\n%s", e.stdin.String())
	t.Logf("STDERR:\n%s", e.stderr.String())
}

type fakeEntryServer struct {
	*entry.UnimplementedEntryServer

	t   *testing.T
	err error

	expGetEntryReq         *entry.GetEntryRequest
	expListEntriesReq      *entry.ListEntriesRequest
	expBatchDeleteEntryReq *entry.BatchDeleteEntryRequest
	expBatchCreateEntryReq *entry.BatchCreateEntryRequest
	expBatchUpdateEntryReq *entry.BatchUpdateEntryRequest

	getEntryResp         *types.Entry
	listEntriesResp      *entry.ListEntriesResponse
	batchDeleteEntryResp *entry.BatchDeleteEntryResponse
	batchCreateEntryResp *entry.BatchCreateEntryResponse
	batchUpdateEntryResp *entry.BatchUpdateEntryResponse
}

func (f fakeEntryServer) ListEntries(ctx context.Context, req *entry.ListEntriesRequest) (*entry.ListEntriesResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	spiretest.RequireProtoEqual(f.t, f.expListEntriesReq, req)
	return f.listEntriesResp, nil
}

func (f fakeEntryServer) GetEntry(ctx context.Context, req *entry.GetEntryRequest) (*types.Entry, error) {
	if f.err != nil {
		return nil, f.err
	}
	spiretest.RequireProtoEqual(f.t, f.expGetEntryReq, req)
	return f.getEntryResp, nil
}

func (f fakeEntryServer) BatchDeleteEntry(ctx context.Context, req *entry.BatchDeleteEntryRequest) (*entry.BatchDeleteEntryResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	spiretest.RequireProtoEqual(f.t, f.expBatchDeleteEntryReq, req)
	return f.batchDeleteEntryResp, nil
}

func (f fakeEntryServer) BatchCreateEntry(ctx context.Context, req *entry.BatchCreateEntryRequest) (*entry.BatchCreateEntryResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	spiretest.RequireProtoEqual(f.t, f.expBatchCreateEntryReq, req)
	return f.batchCreateEntryResp, nil
}

func (f fakeEntryServer) BatchUpdateEntry(ctx context.Context, req *entry.BatchUpdateEntryRequest) (*entry.BatchUpdateEntryResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	spiretest.RequireProtoEqual(f.t, f.expBatchUpdateEntryReq, req)
	return f.batchUpdateEntryResp, nil
}

func setupTest(t *testing.T, newClient func(*common_cli.Env) cli.Command) *entryTest {
	stdin := new(bytes.Buffer)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	client := newClient(&common_cli.Env{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	})

	server := &fakeEntryServer{t: t}
	socketPath := spiretest.StartGRPCSocketServerOnTempSocket(t, func(s *grpc.Server) {
		entry.RegisterEntryServer(s, server)
	})

	test := &entryTest{
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		args:   []string{"-registrationUDSPath", socketPath},
		server: server,
		client: client,
	}

	t.Cleanup(func() {
		test.afterTest(t)
	})

	return test
}
