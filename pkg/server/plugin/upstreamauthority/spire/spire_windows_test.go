//go:build windows

package spireplugin

import (
	"crypto"
	"net"
	"testing"

	"github.com/spiffe/spire/pkg/common/namedpipe"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func configureCasesOS(*testing.T) []configureCase {
	return []configureCase{
		{
			name:                     "success",
			serverAddr:               "localhost",
			serverPort:               "8081",
			workloadAPINamedPipeName: "pipeName",
			expectServerID:           "spiffe://example.org/spire/server",
			expectWorkloadAPIAddr:    namedpipe.AddrFromName("pipeName"),
			expectServerAddr:         "localhost:8081",
		},
		{
			name:              "workload_api_named_pipe_name configured",
			serverAddr:        "localhost",
			serverPort:        "8081",
			workloadAPISocket: "socketPath",
			expectCode:        codes.InvalidArgument,
			expectMsgPrefix:   "unable to set Workload API address: configuration: workload_api_socket is not supported in this platform; please use workload_api_named_pipe_name instead",
		},
	}
}

func mintX509CACasesOS(t *testing.T) []mintX509CACase {
	csr, pubKey, err := util.NewCSRTemplate(trustDomain.IDString())
	require.NoError(t, err)

	return []mintX509CACase{
		{
			name: "invalid socket path",
			getCSR: func() ([]byte, crypto.PublicKey) {
				return csr, pubKey
			},
			customWorkloadAPIAddr: namedpipe.AddrFromName("malformed \000 path"),
			expectCode:            codes.Internal,
			expectMsgPrefix:       `upstreamauthority(spire): unable to create X509Source: parse "passthrough:///\\\\.\\pipe\\malformed \x00 path": net/url: invalid control character in URL`,
		},
	}
}

func setWorkloadAPIAddr(c *Configuration, workloadAPIAddr net.Addr) {
	c.Experimental.WorkloadAPINamedPipeName = namedpipe.GetPipeName(workloadAPIAddr.String())
}
