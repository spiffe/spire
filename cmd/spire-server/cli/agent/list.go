package agent

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/proto/spire/common"

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
	registrationClient registration.RegistrationClient
	nodeList           []*common.AttestedNode
}

func (ListCLI) Synopsis() string {
	return "Lists attested agents and their SPIFFE IDs"
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
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	if err = config.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	if c.registrationClient == nil {
		c.registrationClient, err = util.NewRegistrationClient(config.RegistrationUDSPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error establishing connection to the Registration API: %v \n", err)
			return 1
		}
	}

	listResponse, err := c.registrationClient.ListAgents(ctx, &registration.ListAgentsRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing attested agents: %v \n", err)
		return 1
	}
	c.nodeList = listResponse.Nodes
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
	msg := fmt.Sprintf("Found %d attested ", len(c.nodeList))
	msg = util.Pluralizer(msg, "agent", "agents", len(c.nodeList))
	fmt.Printf(msg + ":\n\n")

	if len(c.nodeList) == 0 {
		return
	}

	for _, node := range c.nodeList {
		fmt.Printf("Spiffe ID         : %s\n", node.SpiffeId)
		fmt.Printf("Attestation type  : %s\n", node.AttestationDataType)
		fmt.Printf("Expiration time   : %s\n", time.Unix(node.CertNotAfter, 0))
		fmt.Printf("Serial number     : %s\n", node.CertSerialNumber)
		fmt.Println()
	}
}
