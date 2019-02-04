package agent

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/proto/api/registration"

	"golang.org/x/net/context"
)

//EvictConfig holds configuration for EvictCLI
type EvictConfig struct {
	// Socket path of registration API
	RegistrationUDSPath string
	// SpiffeID of the agent being evicted
	SpiffeID string
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
	c.SpiffeID, err = idutil.NormalizeSpiffeID(c.SpiffeID, idutil.AllowAnyTrustDomainAgent())
	if err != nil {
		return err
	}

	return nil
}

//EvictCLI command for node eviction
type EvictCLI struct {
	registrationClient registration.RegistrationClient
}

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

	if c.registrationClient == nil {
		c.registrationClient, err = util.NewRegistrationClient(config.RegistrationUDSPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error establishing connection to the Registration API: %v \n", err)
			return 1
		}
	}
	evictResponse, err := c.registrationClient.EvictAgent(ctx, &registration.EvictAgentRequest{SpiffeID: config.SpiffeID})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error evicting agent: %v \n", err)
		return 1
	}

	if evictResponse.Node == nil {
		fmt.Fprintln(os.Stderr, "Failed to evict agent")
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
