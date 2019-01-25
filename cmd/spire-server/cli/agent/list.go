package agent

import (
	"errors"
	"flag"
	"fmt"

	"github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/proto/common"

	"golang.org/x/net/context"
)

type ListConfig struct {
	// Socket path of node API
	NodeUDSPath string
}

// Validate will perform a basic validation on config fields
func (c *ListConfig) Validate() (err error) {
	if c.NodeUDSPath == "" {
		return errors.New("a socket path for node api is required")
	}
	return nil
}

type ListCLI struct{}

func (ListCLI) Synopsis() string {
	return "List agent spiffeIDs"
}

func (c ListCLI) Help() string {
	_, err := c.parseConfig([]string{"-h"})
	return err.Error()
}

func (c ListCLI) Run(args []string) int {
	ctx := context.Background()

	config, err := c.parseConfig(args)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	if err = config.Validate(); err != nil {
		fmt.Println(err.Error())
		return 1
	}

	nodeClient, err := util.NewNodeClient(config.NodeUDSPath)
	if err != nil {
		fmt.Printf("Error creating node client: %v \n", err)
		return 1
	}

	listResponse, err := nodeClient.List(ctx, &common.Empty{})
	if err != nil {
		fmt.Printf("Error listing nodes: %v \n", err)
		return 1
	}

	printAttestedNodes(listResponse.Nodes)
	return 0
}

func (ListCLI) parseConfig(args []string) (*ListConfig, error) {
	f := flag.NewFlagSet("agent list", flag.ContinueOnError)
	c := &ListConfig{}

	f.StringVar(&c.NodeUDSPath, "nodeUDSPath", util.DefaultSocketPath, "Node API UDS path")

	return c, f.Parse(args)
}

func printAttestedNodes(nodeList []*common.AttestedNode) {
	if len(nodeList) == 0 {
		fmt.Println("Found 0 attested agents")
		return
	}

	fmt.Printf("Attested nodes:\n\n")
	for _, node := range nodeList {
		fmt.Println(node.SpiffeId)
	}
}
