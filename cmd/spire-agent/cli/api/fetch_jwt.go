package api

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
)

func NewFetchJWTCommand() cli.Command {
	return newFetchJWTCommand(common_cli.DefaultEnv, newWorkloadClient)
}

func newFetchJWTCommand(env *common_cli.Env, clientMaker workloadClientMaker) cli.Command {
	return adaptCommand(env, clientMaker, new(fetchJWTCommand))
}

type fetchJWTCommand struct {
	audience common_cli.CommaStringsFlag
	spiffeID string
	format string
}

func (c *fetchJWTCommand) name() string {
	return "fetch jwt"
}

func (c *fetchJWTCommand) synopsis() string {
	return "Fetches a JWT SVID from the Workload API"
}

func (c *fetchJWTCommand) run(ctx context.Context, env *common_cli.Env, client *workloadClient) error {
	if len(c.audience) == 0 {
		return errors.New("audience must be specified")
	}

	if len(c.format) != 0 && c.format != "json" {

		return errors.New("format currently can only be json")
	}

	bundlesResp, err := c.fetchJWTBundles(ctx, client)
	if err != nil {
		return err
	}
	svidResp, err := c.fetchJWTSVID(ctx, client)
	if err != nil {
		return err
	}

	if c.format != "" {
		if c.format == "json" {
			sep := ""
			fmt.Printf("{\n    \"tokens\": {\n")
			for i, svid := range svidResp.Svids {
				if i == len(svidResp.Svids) - 1 {
					sep = ""
				} else {
					sep = ","
				}
				fmt.Printf("        \"%s\": \"%s\"%s\n", svid.SpiffeId, svid.Svid, sep)
			}
			fmt.Printf("    },\n    \"bundles\": {\n")
			i := 0
			for trustDomainID, jwksJSON := range bundlesResp.Bundles {
				if i == len(bundlesResp.Bundles) - 1 {
					sep = ""
				} else {
					sep = ","
				}
				s := strings.Replace(strings.TrimSpace(string(jwksJSON)), "\n", "\n        ", -1)
				fmt.Printf("        \"%s\": %s%s\n", trustDomainID, s, sep)
				i += 1
			}
			fmt.Printf("    }\n}\n")
		}
	} else {

		for _, svid := range svidResp.Svids {
			fmt.Printf("token(%s):\n\t%s\n", svid.SpiffeId, svid.Svid)
		}

		for trustDomainID, jwksJSON := range bundlesResp.Bundles {
			fmt.Printf("bundle(%s):\n\t%s\n", trustDomainID, string(jwksJSON))
		}
	}
	return nil
}

func (c *fetchJWTCommand) appendFlags(fs *flag.FlagSet) {
	fs.Var(&c.audience, "audience", "comma separated list of audience values")
	fs.StringVar(&c.spiffeID, "spiffeID", "", "SPIFFE ID subject (optional)")
	fs.StringVar(&c.format, "format", "", "format [json] (optional)")
}

func (c *fetchJWTCommand) fetchJWTSVID(ctx context.Context, client *workloadClient) (*workload.JWTSVIDResponse, error) {
	ctx, cancel := client.prepareContext(ctx)
	defer cancel()
	return client.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{
		Audience: c.audience,
		SpiffeId: c.spiffeID,
	})
}

func (c *fetchJWTCommand) fetchJWTBundles(ctx context.Context, client *workloadClient) (*workload.JWTBundlesResponse, error) {
	ctx, cancel := client.prepareContext(ctx)
	defer cancel()
	stream, err := client.FetchJWTBundles(ctx, &workload.JWTBundlesRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to receive JWT bundles: %w", err)
	}
	return stream.Recv()
}
