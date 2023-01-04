package api

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

func NewFetchJWTCommand() cli.Command {
	return newFetchJWTCommand(commoncli.DefaultEnv, newWorkloadClient)
}

func newFetchJWTCommand(env *commoncli.Env, clientMaker workloadClientMaker) cli.Command {
	return adaptCommand(env, clientMaker, new(fetchJWTCommand))
}

type fetchJWTCommand struct {
	audience commoncli.CommaStringsFlag
	spiffeID string
	printer  cliprinter.Printer
}

func (c *fetchJWTCommand) name() string {
	return "fetch jwt"
}

func (c *fetchJWTCommand) synopsis() string {
	return "Fetches a JWT SVID from the Workload API"
}

func (c *fetchJWTCommand) run(ctx context.Context, env *commoncli.Env, client *workloadClient) error {
	if len(c.audience) == 0 {
		return errors.New("audience must be specified")
	}

	bundlesResp, err := c.fetchJWTBundles(ctx, client)
	if err != nil {
		return err
	}
	svidResp, err := c.fetchJWTSVID(ctx, client)
	if err != nil {
		return err
	}

	return c.printer.PrintProto(svidResp, bundlesResp)
}

func (c *fetchJWTCommand) appendFlags(fs *flag.FlagSet) {
	fs.Var(&c.audience, "audience", "comma separated list of audience values")
	fs.StringVar(&c.spiffeID, "spiffeID", "", "SPIFFE ID subject (optional)")
	outputValue := cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, nil, printPrettyResult)
	fs.Var(outputValue, "format", "deprecated; use -output")
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

func printPrettyResult(_ *commoncli.Env, results ...interface{}) error {
	errMsg := "internal error: cli printer; please report this bug"

	svidResp, ok := results[0].(*workload.JWTSVIDResponse)
	if !ok {
		fmt.Println(errMsg)
		return errors.New(errMsg)
	}

	bundlesResp, ok := results[1].(*workload.JWTBundlesResponse)
	if !ok {
		fmt.Println(errMsg)
		return errors.New(errMsg)
	}

	for _, svid := range svidResp.Svids {
		fmt.Printf("token(%s):\n\t%s\n", svid.SpiffeId, svid.Svid)
	}

	for trustDomainID, jwksJSON := range bundlesResp.Bundles {
		fmt.Printf("bundle(%s):\n\t%s\n", trustDomainID, string(jwksJSON))
	}

	return nil
}
