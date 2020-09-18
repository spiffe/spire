package agent

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire/proto/spire/types"

	"golang.org/x/net/context"
)

//EvictConfig holds configuration for EvictCLI
type EvictConfig struct {
	// Socket path of registration API
	RegistrationUDSPath string
	// SpiffeID of the agent being evicted
	SpiffeID string

	agentID *types.SPIFFEID
}

// Validate will perform a basic validation on config fields
func (c *EvictConfig) Validate() (err error) {
	if c.RegistrationUDSPath == "" {
		return errors.New("a socket path for registration api is required")
	}

	if c.SpiffeID == "" {
		return errors.New("a SPIFFE ID is required")
	}

	// make sure SPIFFE ID is well formed
	agentID, err := spiffeid.FromString(c.SpiffeID)
	if err != nil {
		return fmt.Errorf("invalid SPIFFE ID: %v", err)
	}

	if err := api.VerifyAnyTrustDomainAgentID(agentID); err != nil {
		return err
	}

	c.agentID = api.ProtoFromID(agentID)
	return nil
}

//EvictCLI command for node eviction
type EvictCLI struct{}

func (EvictCLI) Synopsis() string {
	return "Evicts an attested agent given its SPIFFE ID"
}

func (c EvictCLI) Help() string {
	_, err := c.parseConfig([]string{"-h"})
	return err.Error()
}

//Run will evict an agent given its spiffeID
func (c EvictCLI) Run(args []string) int {
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

	serverConn, err := util.Dial(config.RegistrationUDSPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to dial SPIRE server: %v\n", err)
		return 1
	}
	defer serverConn.Close()

	agentClient := agent.NewAgentClient(serverConn)

	if _, err := agentClient.DeleteAgent(ctx, &agent.DeleteAgentRequest{Id: config.agentID}); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to evict agent: %v\n", err)
		return 1
	}

	fmt.Println("Agent evicted successfully")
	return 0
}

func (EvictCLI) parseConfig(args []string) (*EvictConfig, error) {
	f := flag.NewFlagSet("agent evict", flag.ContinueOnError)
	c := &EvictConfig{}

	f.StringVar(&c.RegistrationUDSPath, "registrationUDSPath", util.DefaultSocketPath, "Registration API UDS path")
	f.StringVar(&c.SpiffeID, "spiffeID", "", "The SPIFFE ID of the agent to evict (agent identity)")

	return c, f.Parse(args)
}
