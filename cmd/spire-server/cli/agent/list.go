package agent

import (
	"errors"
	"flag"
	"fmt"

	"github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"

	"golang.org/x/net/context"
)

//ListConfig holds configuration for ListCLI
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

//ListCLI command for listing attested nodes
type ListCLI struct {
	RegistrationClient registration.RegistrationClient
	NodeList           []*common.AttestedNode
}

func (ListCLI) Synopsis() string {
	return "List agent spiffeIDs"
}

func (c ListCLI) Help() string {
	_, err := c.parseConfig([]string{"-h"})
	return err.Error()
}

//Run will lists attested agents
func (c *ListCLI) Run(args []string) int {
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

	if c.RegistrationClient == nil {
		c.RegistrationClient, err = util.NewRegistrationClient(config.RegistrationUDSPath)
		if err != nil {
			fmt.Printf("Error creating registration client: %v \n", err)
			return 1
		}
	}

	listResponse, err := c.RegistrationClient.ListAgents(ctx, &common.Empty{})
	if err != nil {
		fmt.Printf("Error listing attested nodes: %v \n", err)
		return 1
	}
	c.NodeList = listResponse.Nodes
	c.printAttestedNodes()
	return 0
}

func (ListCLI) parseConfig(args []string) (*ListConfig, error) {
	f := flag.NewFlagSet("agent list", flag.ContinueOnError)
	c := &ListConfig{}

	f.StringVar(&c.RegistrationUDSPath, "registrationUDSPath", util.DefaultSocketPath, "Registration API UDS path")

	return c, f.Parse(args)
}

func (c ListCLI) printAttestedNodes() {
	msg := "Found %v attested "
	msg = util.Pluralizer(msg, "agent", "agents", len(c.NodeList))
	fmt.Printf(msg+":\n\n", len(c.NodeList))

	if len(c.NodeList) == 0 {
		return
	}

	fmt.Println("Serial \t\t SpiffeID")
	for _, node := range c.NodeList {
		fmt.Printf("%s \t\t %s\n", node.CertSerialNumber, node.SpiffeId)
	}
}
