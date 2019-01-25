package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"

	go_plugin "github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
)

func fatalf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) != 3 {
		fatalf("Usage: %s <plugin_binary> <pid>", os.Args[0])
	}
	pluginName := os.Args[1]
	pid, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fatalf("Failed to convert pid arg to int: %v", err)
	}
	config := &go_plugin.ClientConfig{
		HandshakeConfig: workloadattestor.Handshake,
		Plugins: map[string]go_plugin.Plugin{
			"workloadattestor": &workloadattestor.GRPCPlugin{},
		},
		Cmd:              exec.Command(pluginName),
		AllowedProtocols: []go_plugin.Protocol{go_plugin.ProtocolGRPC},
		Managed:          true,
	}

	client, err := go_plugin.NewClient(config).Client()
	if err != nil {
		fatalf("Failed to create new plugin client: %v", err)
	}
	defer client.Close()

	raw, err := client.Dispense("workloadattestor")
	if err != nil {
		fatalf("Failed to dispense plugin client: %v", err)
	}

	plugin, ok := raw.(*workloadattestor.GRPCClient)
	if !ok {
		fatalf("Failed to type assert raw client (type %T) to type *workloadattestor.GRPCClient", raw)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	res, err := plugin.Attest(ctx, &workloadattestor.AttestRequest{Pid: int32(pid)})
	if err != nil {
		fatalf("Failed to attest pid %d: %v", pid, err)
	}

	fmt.Println(res)
}
