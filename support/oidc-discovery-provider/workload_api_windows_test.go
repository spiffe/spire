//go:build windows
// +build windows

package main

import (
	"net"
	"testing"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/test/spiretest"
)

func startWorkloadAPI(t *testing.T, server workload.SpiffeWorkloadAPIServer) net.Addr {
	return util.GetNamedPipeAddr(util.GetPipeName(spiretest.StartWorkloadAPI(t, server).String()))
}
