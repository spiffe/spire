//go:build !windows
// +build !windows

package spireplugin

import (
	"crypto"
	"net"
	"testing"

	addr_util "github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func configureCasesOS(t *testing.T) []configureCase {
	addr, err := addr_util.GetUnixAddrWithAbsPath("socketPath")
	require.NoError(t, err)
	return []configureCase{
		{
			name:                  "success",
			serverAddr:            "localhost",
			serverPort:            "8081",
			workloadAPISocket:     "socketPath",
			expectServerID:        "spiffe://example.org/spire/server",
			expectWorkloadAPIAddr: addr,
			expectServerAddr:      "localhost:8081",
		},
		{
			name:                     "workload_api_named_pipe_name configured",
			serverAddr:               "localhost",
			serverPort:               "8081",
			workloadAPINamedPipeName: "socketPath",
			expectCode:               codes.InvalidArgument,
			expectMsgPrefix:          "unable to set Workload API address: configuration: workload_api_named_pipe_name is not supported in this platform; please use workload_api_socket instead",
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
			customWorkloadAPIAddr: addr_util.GetUnixAddr("malformed \000 path"),
			expectCode:            codes.Internal,
			expectMsgPrefix:       `upstreamauthority(spire): unable to create X509Source: workload endpoint socket is not a valid URI: parse "unix://`,
		},
	}
}

func setWorkloadAPIAddr(c *Configuration, workloadAPIAddr net.Addr) {
	c.WorkloadAPISocket = workloadAPIAddr.String()
}
