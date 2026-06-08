//go:build windows

package debug

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/namedpipe"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc"
)

var (
	usage = `Usage of debug getinfo:
  -namedPipeName string
    	Pipe name of the SPIRE Agent admin API named pipe (default "\\spire-agent\\private\\admin")
  -output value
    	Desired output format (pretty, json); default: pretty.
`
	socketAddrArg         = "-namedPipeName"
	socketAddrUnavailable = "doesnotexist"
)

func startGRPCSocketServer(t *testing.T, registerFn func(srv *grpc.Server)) string {
	return namedpipe.GetPipeName(spiretest.StartGRPCServer(t, registerFn).String())
}
