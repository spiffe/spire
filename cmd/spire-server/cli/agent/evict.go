package agent

import (
	"errors"
	"flag"
	"fmt"

	"github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/proto/api/node"

	"golang.org/x/net/context"
)

type EvictConfig struct {
	// Socket path of node API
	NodeUDSPath string
	// SpiffeID of the agent being evicted
	SpiffeID string
}

// Validate will perform a basic validation on config fields
func (c *EvictConfig) Validate() (err error) {
	if c.NodeUDSPath == "" {
		return errors.New("a socket path for node api is required")
	}

	if c.SpiffeID == "" {
		return errors.New("a SPIFFE ID is required")
	}

	// make sure SPIFFE ID is well formed
	c.SpiffeID, err = idutil.NormalizeSpiffeID(c.SpiffeID, idutil.AllowAny())
	if err != nil {
		return err
	}

	return nil
}

type EvictCLI struct{}

func (EvictCLI) Synopsis() string {
	return "De-attest an agent givent its spiffeID"
}

func (c EvictCLI) Help() string {
	_, err := c.parseConfig([]string{"-h"})
	return err.Error()
}

func (c EvictCLI) Run(args []string) int {
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

	evictResponse, err := nodeClient.Evict(ctx, &node.EvictRequest{SpiffeID: config.SpiffeID})
	if err != nil {
		fmt.Printf("Error de-attesting agent: %v \n", err)
		return 1
	}

	if !evictResponse.DeleteSucceed {
		fmt.Println("Failed to de-attest agent")
	}

	fmt.Println("Agent de-attested successfully")
	return 0
}

func (EvictCLI) parseConfig(args []string) (*EvictConfig, error) {
	f := flag.NewFlagSet("agent evict", flag.ContinueOnError)
	c := &EvictConfig{}

	f.StringVar(&c.NodeUDSPath, "nodeUDSPath", util.DefaultSocketPath, "Node API UDS path")
	f.StringVar(&c.SpiffeID, "spiffeID", "", "The SPIFFE ID of the agent to evict (core identity)")

	return c, f.Parse(args)
}
