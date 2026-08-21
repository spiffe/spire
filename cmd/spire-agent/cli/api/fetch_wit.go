package api

import (
	"context"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

func NewFetchWITCommand() cli.Command {
	return newFetchWITCommandWithEnv(commoncli.DefaultEnv, newWorkloadClient)
}

func newFetchWITCommandWithEnv(env *commoncli.Env, clientMaker workloadClientMaker) cli.Command {
	return adaptCommand(env, clientMaker, &fetchWITCommand{env: env})
}

type fetchWITCommand struct {
	spiffeID string
	printer  cliprinter.Printer
	env      *commoncli.Env
}

func (c *fetchWITCommand) name() string {
	return "fetch wit"
}

func (c *fetchWITCommand) synopsis() string {
	return "Fetches a WIT-SVID from the Workload API"
}

func (c *fetchWITCommand) run(ctx context.Context, _ *commoncli.Env, client *workloadClient) error {
	bundlesResp, err := c.fetchWITBundles(ctx, client)
	if err != nil {
		return err
	}
	svidResp, err := c.fetchWITSVID(ctx, client)
	if err != nil {
		return err
	}

	return c.printer.PrintProto(svidResp, bundlesResp)
}

func (c *fetchWITCommand) appendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.spiffeID, "spiffeID", "", "SPIFFE ID subject (optional)")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, printPrettyWITResult)
}

func (c *fetchWITCommand) fetchWITSVID(ctx context.Context, client *workloadClient) (*workload.WITSVIDResponse, error) {
	ctx, cancel := client.prepareContext(ctx)
	defer cancel()
	stream, err := client.FetchWITSVID(ctx, &workload.WITSVIDRequest{
		SpiffeId: c.spiffeID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to receive WIT-SVIDs: %w", err)
	}
	return stream.Recv()
}

func (c *fetchWITCommand) fetchWITBundles(ctx context.Context, client *workloadClient) (*workload.WITBundlesResponse, error) {
	ctx, cancel := client.prepareContext(ctx)
	defer cancel()
	stream, err := client.FetchWITBundles(ctx, &workload.WITBundlesRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to receive WIT bundles: %w", err)
	}
	return stream.Recv()
}

func printPrettyWITResult(env *commoncli.Env, results ...any) error {
	svidResp, ok := results[0].(*workload.WITSVIDResponse)
	if !ok {
		env.Println(cliprinter.ErrInternalCustomPrettyFunc.Error())
		return cliprinter.ErrInternalCustomPrettyFunc
	}

	bundlesResp, ok := results[1].(*workload.WITBundlesResponse)
	if !ok {
		env.Println(cliprinter.ErrInternalCustomPrettyFunc.Error())
		return cliprinter.ErrInternalCustomPrettyFunc
	}

	for _, svid := range svidResp.Svids {
		env.Printf("token(%s):\n\t%s\n", svid.SpiffeId, svid.WitSvid)
		env.Printf("key(%s):\n\t%s\n", svid.SpiffeId, svid.WitSvidKey)
		if svid.Hint != "" {
			env.Printf("hint(%s):\n\t%s\n", svid.SpiffeId, svid.Hint)
		}
	}

	for trustDomainID, jwksJSON := range bundlesResp.Bundles {
		env.Printf("bundle(%s):\n\t%s\n", trustDomainID, jwksJSON)
	}

	return nil
}
