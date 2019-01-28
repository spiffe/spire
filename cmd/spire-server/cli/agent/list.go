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
	// Socket path of registration API
	RegistrationUDSPath string
}

// Validate will perform a basic validation on config fields
func (c *ListConfig) Validate() (err error) {
	if c.RegistrationUDSPath == "" {
		return errors.New("a socket path for registration api is required")
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

	registrationClient, err := util.NewRegistrationClient(config.RegistrationUDSPath)
	if err != nil {
		fmt.Printf("Error creating registration client: %v \n", err)
		return 1
	}

	listResponse, err := registrationClient.ListAgents(ctx, &common.Empty{})
	if err != nil {
		fmt.Printf("Error listing attested nodes: %v \n", err)
		return 1
	}

	printAttestedNodes(listResponse.Nodes)
	return 0
}

func (ListCLI) parseConfig(args []string) (*ListConfig, error) {
	f := flag.NewFlagSet("agent list", flag.ContinueOnError)
	c := &ListConfig{}

	f.StringVar(&c.RegistrationUDSPath, "registrationUDSPath", util.DefaultSocketPath, "Registration API UDS path")

	return c, f.Parse(args)
}

func printAttestedNodes(nodeList []*common.AttestedNode) {
	msg := "Found %v attested "
	msg = util.Pluralizer(msg, "agent", "agents", len(nodeList))
	fmt.Printf(msg+":\n\n", len(nodeList))

	if len(nodeList) == 0 {
		return
	}

	fmt.Println("Serial \t\t SpiffeID")
	for _, node := range nodeList {
		fmt.Printf("%s \t\t %s\n", node.CertSerialNumber, node.SpiffeId)
	}
}
