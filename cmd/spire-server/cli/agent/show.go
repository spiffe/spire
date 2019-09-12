package agent

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/proto/spire/common"

	"golang.org/x/net/context"
)

// ShowConfig holds configuration for ShowCLI
type ShowConfig struct {
	// Socket path of registration API
	RegistrationUDSPath string
	// SpiffeID of the agent being showed
	SpiffeID string
}

// Validate will perform a basic validation on config fields
func (c *ShowConfig) Validate() (err error) {
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

// ShowCLI command for listing attested nodes
type ShowCLI struct {
	registrationClient registration.RegistrationClient
	node               *common.AttestedNode
	selectors          []*common.Selector
}

func (ShowCLI) Synopsis() string {
	return "Shows the details of an attested agent given its SPIFFE ID"
}

func (c ShowCLI) Help() string {
	_, err := c.parseConfig([]string{"-h"})
	return err.Error()
}

// Run will show the details of an attested agent given its SPIFFE ID
func (c *ShowCLI) Run(args []string) int {
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

	for _, node := range listResponse.Nodes {
		if node.SpiffeId == config.SpiffeID {
			c.node = node
			break
		}
	}

	if c.node == nil {
		fmt.Println("Not found an attested agent given its SPIFFE ID")
		return 1
	}

	c.selectors, err = c.fetchSelectors(ctx, config.SpiffeID)
	if err != nil {
		fmt.Printf("Error fetching selectors by SPIFFE ID: %s", err)
		return 1
	}

	c.printAttestedNode()
	return 0
}

func (ShowCLI) parseConfig(args []string) (*ShowConfig, error) {
	f := flag.NewFlagSet("agent show", flag.ContinueOnError)
	c := &ShowConfig{}

	f.StringVar(&c.RegistrationUDSPath, "registrationUDSPath", util.DefaultSocketPath, "Registration API UDS path")
	f.StringVar(&c.SpiffeID, "spiffeID", "", "The SPIFFE ID of the agent to show (agent identity)")

	return c, f.Parse(args)
}

// fetchSelectors fetches selectors of an attested agent given its SPIFFE ID
func (c ShowCLI) fetchSelectors(ctx context.Context, spiffeID string) ([]*common.Selector, error) {
	selectorsResp, err := c.registrationClient.GetNodeSelectors(ctx,
		&registration.GetNodeSelectorsRequest{
			SpiffeId: spiffeID,
		})
	if err != nil {
		return nil, err
	}

	if selectorsResp.Selectors == nil {
		return nil, errors.New("response missing selectors")
	}

	// No need to look for more entries if we didn't get any selectors
	selectors := selectorsResp.Selectors.Selectors
	if len(selectors) < 1 {
		return nil, nil
	}

	return selectors, nil
}

func (c ShowCLI) printAttestedNode() {
	fmt.Printf("Found an attested agent given its SPIFFE ID\n\n")
	fmt.Printf("Spiffe ID         : %s\n", c.node.SpiffeId)
	fmt.Printf("Attestation type  : %s\n", c.node.AttestationDataType)
	fmt.Printf("Expiration time   : %s\n", time.Unix(c.node.CertNotAfter, 0))
	fmt.Printf("Serial number     : %s\n", c.node.CertSerialNumber)

	if c.selectors != nil {
		for _, s := range c.selectors {
			fmt.Printf("Selectors         : %s:%s\n", s.Type, s.Value)
		}
	}

	fmt.Println()
}
