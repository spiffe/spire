package entry

import (
	"bytes"
	"os"
	"path"
	"testing"

	"github.com/mitchellh/cli"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/cli/common"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var availableFormats = []string{"pretty", "json"}

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
				data, err := os.ReadFile(testCase.testDataPath)
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
				SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/Blog"},
				ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenBlog"},
				X509SvidTtl: 200,
				JwtSvidTtl:  30,
				Admin:       true,
			}
			entry2 := &types.Entry{
				Selectors: []*types.Selector{
					{
						Type:  "unix",
						Value: "uid:1111",
					},
				},
				SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/Database"},
				ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenDatabase"},
				X509SvidTtl: 200,
				JwtSvidTtl:  30,
				Hint:        "internal",
			}
			entry3 := &types.Entry{
				Selectors: []*types.Selector{
					{
						Type:  "type",
						Value: "key1:value",
					},
					{
						Type:  "type",
						Value: "key2:value",
					},
				},
				SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/storesvid"},
				ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenDatabase"},
				StoreSvid:   true,
				X509SvidTtl: 200,
				JwtSvidTtl:  30,
			}

			expectedEntries := []*types.Entry{
				entry1,
				entry2,
				entry3,
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

	addr   string
	server *fakeEntryServer

	client cli.Command
}

func (e *entryTest) afterTest(t *testing.T) {
	t.Logf("TEST:%s", t.Name())
	t.Logf("STDOUT:\n%s", e.stdout.String())
	t.Logf("STDIN:\n%s", e.stdin.String())
	t.Logf("STDERR:\n%s", e.stderr.String())
}

func (e *entryTest) args(extra ...string) []string {
	return append([]string{common.AddrArg, e.addr}, extra...)
}

type fakeEntryServer struct {
	*entryv1.UnimplementedEntryServer

	t   *testing.T
	err error

	expGetEntryReq         *entryv1.GetEntryRequest
	expListEntriesReq      *entryv1.ListEntriesRequest
	expBatchDeleteEntryReq *entryv1.BatchDeleteEntryRequest
	expBatchCreateEntryReq *entryv1.BatchCreateEntryRequest
	expBatchUpdateEntryReq *entryv1.BatchUpdateEntryRequest

	getEntryResp         *types.Entry
	countEntriesResp     *entryv1.CountEntriesResponse
	listEntriesResp      *entryv1.ListEntriesResponse
	batchDeleteEntryResp *entryv1.BatchDeleteEntryResponse
	batchCreateEntryResp *entryv1.BatchCreateEntryResponse
	batchUpdateEntryResp *entryv1.BatchUpdateEntryResponse
}

func (f fakeEntryServer) CountEntries(context.Context, *entryv1.CountEntriesRequest) (*entryv1.CountEntriesResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.countEntriesResp, nil
}

func (f fakeEntryServer) ListEntries(_ context.Context, req *entryv1.ListEntriesRequest) (*entryv1.ListEntriesResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	spiretest.AssertProtoEqual(f.t, f.expListEntriesReq, req)
	return f.listEntriesResp, nil
}

func (f fakeEntryServer) GetEntry(_ context.Context, req *entryv1.GetEntryRequest) (*types.Entry, error) {
	if f.err != nil {
		return nil, f.err
	}
	spiretest.AssertProtoEqual(f.t, f.expGetEntryReq, req)
	return f.getEntryResp, nil
}

func (f fakeEntryServer) BatchDeleteEntry(_ context.Context, req *entryv1.BatchDeleteEntryRequest) (*entryv1.BatchDeleteEntryResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	spiretest.AssertProtoEqual(f.t, f.expBatchDeleteEntryReq, req)
	return f.batchDeleteEntryResp, nil
}

func (f fakeEntryServer) BatchCreateEntry(_ context.Context, req *entryv1.BatchCreateEntryRequest) (*entryv1.BatchCreateEntryResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	spiretest.AssertProtoEqual(f.t, f.expBatchCreateEntryReq, req)
	return f.batchCreateEntryResp, nil
}

func (f fakeEntryServer) BatchUpdateEntry(_ context.Context, req *entryv1.BatchUpdateEntryRequest) (*entryv1.BatchUpdateEntryResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	spiretest.AssertProtoEqual(f.t, f.expBatchUpdateEntryReq, req)
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
	addr := spiretest.StartGRPCServer(t, func(s *grpc.Server) {
		entryv1.RegisterEntryServer(s, server)
	})

	test := &entryTest{
		addr:   common.GetAddr(addr),
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		server: server,
		client: client,
	}

	t.Cleanup(func() {
		test.afterTest(t)
	})

	return test
}

func requireOutputBasedOnFormat(t *testing.T, format, stdoutString string, expectedStdoutPretty, expectedStdoutJSON string) {
	switch format {
	case "pretty":
		require.Contains(t, stdoutString, expectedStdoutPretty)
	case "json":
		if expectedStdoutJSON != "" {
			require.JSONEq(t, expectedStdoutJSON, stdoutString)
		} else {
			require.Empty(t, stdoutString)
		}
	}
}
