package token

import (
	"flag"
	"fmt"
	"net/url"
	"path"

	"github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"

	"golang.org/x/net/context"
)

type GenerateCLI struct{}

type GenerateConfig struct {
	// Socket path of registration API
	RegistrationUDSPath string

	// Optional SPIFFE ID to create with the token
	SpiffeID string

	// Token TTL in seconds
	TTL int
}

func (GenerateCLI) Synopsis() string {
	return "Generates a join token"
}

func (g GenerateCLI) Help() string {
	_, err := g.newConfig([]string{"-h"})
	return err.Error()
}

func (g GenerateCLI) Run(args []string) int {
	ctx := context.Background()

	config, err := g.newConfig(args)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	c, err := util.NewRegistrationClient(config.RegistrationUDSPath)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	token, err := g.createToken(ctx, c, config.TTL)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}
	fmt.Printf("Token: %s\n", token)

	if config.SpiffeID != "" {
		err = g.createVanityRecord(ctx, c, token, config.SpiffeID)
		if err != nil {
			fmt.Printf("Error assigning SPIFFE ID: %s\n", err.Error())
			return 1
		}
	}

	return 0
}

// createToken calls the registration API and creates a new token
// with the given TTL. It returns the raw token and an error, if any
func (GenerateCLI) createToken(ctx context.Context, c registration.RegistrationClient, ttl int) (string, error) {
	req := &registration.JoinToken{Ttl: int32(ttl)}
	resp, err := c.CreateJoinToken(ctx, req)
	if err != nil {
		return "", err
	}

	return resp.Token, nil
}

// createVanityRecord inserts a registration entry with parent ID set to the SPIFFE ID
// belonging to a token. The purpose is to allow folks to easily create vanity names
// backed by token IDs.
func (GenerateCLI) createVanityRecord(ctx context.Context, c registration.RegistrationClient, token, spiffeID string) error {
	id, err := url.Parse(spiffeID)
	if err != nil {
		return fmt.Errorf("could not parse SPIFFE ID: %s", err.Error())
	}

	// Basic sanity check before calling the server
	if id.Scheme != "spiffe" || id.Host == "" || id.Path == "" {
		return fmt.Errorf("\"%s\" is not a valid SPIFFE ID", id.String())
	}

	parentID := &url.URL{
		Scheme: id.Scheme,
		Host:   id.Host,
		Path:   path.Join("spire", "agent", "join_token", token),
	}
	req := &common.RegistrationEntry{
		ParentId: parentID.String(),
		SpiffeId: id.String(),
		Selectors: []*common.Selector{
			{Type: "spiffe_id", Value: parentID.String()},
		},
	}

	_, err = c.CreateEntry(ctx, req)
	if err != nil {
		return err
	}

	return nil
}

func (GenerateCLI) newConfig(args []string) (GenerateConfig, error) {
	flags := flag.NewFlagSet("generate", flag.ContinueOnError)
	c := GenerateConfig{}

	flags.IntVar(&c.TTL, "ttl", 600, "Token TTL in seconds")
	flags.StringVar(&c.SpiffeID, "spiffeID", "", "Additional SPIFFE ID to assign the token owner (optional)")
	flags.StringVar(&c.RegistrationUDSPath, "registrationUDSPath", util.DefaultSocketPath, "Registration API UDS path")

	err := flags.Parse(args)
	if err != nil {
		return c, err
	}

	return c, nil
}
