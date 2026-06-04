package api

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"time"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"github.com/spiffe/spire/pkg/common/diskutil"
)

func NewFetchWITCommand() cli.Command {
	return newFetchWITCommandWithEnv(commoncli.DefaultEnv, newWorkloadClient)
}

func newFetchWITCommandWithEnv(env *commoncli.Env, clientMaker workloadClientMaker) cli.Command {
	return adaptCommand(env, clientMaker, &fetchWITCommand{env: env})
}

type fetchWITCommand struct {
	silent    bool
	writePath string
	printer   cliprinter.Printer
	env       *commoncli.Env
	respTime  time.Duration
}

func (c *fetchWITCommand) name() string {
	return "fetch wit"
}

func (c *fetchWITCommand) synopsis() string {
	return "Fetches a WIT SVID from the Workload API"
}

func (c *fetchWITCommand) run(ctx context.Context, _ *commoncli.Env, client *workloadClient) error {
	bundlesResp, err := c.fetchWITBundles(ctx, client)
	if err != nil {
		return err
	}

	start := time.Now()
	svidResp, err := c.fetchWITSVID(ctx, client)
	if err != nil {
		return err
	}
	c.respTime = time.Since(start)

	return c.printer.PrintProto(svidResp, bundlesResp)
}

func (c *fetchWITCommand) appendFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.silent, "silent", false, "Suppress stdout")
	fs.StringVar(&c.writePath, "write", "", "Write SVID data to the specified path (optional; only available for pretty output format)")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, c.prettyPrintFetchWIT)
}

func (c *fetchWITCommand) fetchWITSVID(ctx context.Context, client *workloadClient) (*workload.WITSVIDResponse, error) {
	ctx, cancel := client.prepareContext(ctx)
	defer cancel()

	stream, err := client.FetchWITSVID(ctx, &workload.WITSVIDRequest{})
	if err != nil {
		return nil, err
	}

	return stream.Recv()
}

func (c *fetchWITCommand) fetchWITBundles(ctx context.Context, client *workloadClient) (*workload.WITBundlesResponse, error) {
	ctx, cancel := client.prepareContext(ctx)
	defer cancel()
	stream, err := client.FetchWITBundles(ctx, &workload.WITBundlesRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to receive JWT bundles: %w", err)
	}
	return stream.Recv()
}

func (c *fetchWITCommand) prettyPrintFetchWIT(env *commoncli.Env, results ...any) error {
	resp, ok := results[0].(*workload.WITSVIDResponse)
	if !ok {
		return cliprinter.ErrInternalCustomPrettyFunc
	}

	if !c.silent {
		printWITSVIDResponse(env, resp.Svids, c.respTime)
	}

	if c.writePath != "" {
		if err := c.writeResponse(resp.Svids); err != nil {
			return err
		}
	}

	return nil
}

func (c *fetchWITCommand) writeResponse(svids []*workload.WITSVID) error {
	for i, svid := range svids {
		svidPath := filepath.Join(c.writePath, fmt.Sprintf("svid.%v.token", i))
		keyPath := filepath.Join(c.writePath, fmt.Sprintf("svid.%v.key", i))

		c.env.Printf("Writing SVID #%d to file %s.\n", i, svidPath)
		err := c.writeFile(svidPath, []byte(svid.WitSvid))
		if err != nil {
			return err
		}

		c.env.Printf("Writing key #%d to file %s.\n", i, keyPath)
		err = c.writeFile(keyPath, []byte(svid.WitSvidKey))
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *fetchWITCommand) writeFile(filename string, data []byte) error {
	return diskutil.WritePubliclyReadableFile(filename, data)
}
