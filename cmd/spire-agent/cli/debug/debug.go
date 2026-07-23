package debug

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/mitchellh/cli"
	debugv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/debug/v1"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"github.com/spiffe/spire/pkg/common/util"
)

// NewGetInfoCommand creates a new "debug getinfo" subcommand for "debug" command.
func NewGetInfoCommand() cli.Command {
	return newGetInfoCommand(commoncli.DefaultEnv)
}

func newGetInfoCommand(env *commoncli.Env) *getInfoCommand {
	return &getInfoCommand{
		env: env,
	}
}

type getInfoCommand struct {
	getInfoCommandOS

	env     *commoncli.Env
	printer cliprinter.Printer
}

func (c *getInfoCommand) Help() string {
	_ = c.parseFlags([]string{"-h"})
	return ""
}

func (c *getInfoCommand) Synopsis() string {
	return "Prints debug information about the agent"
}

func (c *getInfoCommand) Run(args []string) int {
	if err := c.parseFlags(args); err != nil {
		return 1
	}
	if err := c.run(); err != nil {
		_ = c.env.ErrPrintf("Error: %v\n", err)
		return 1
	}
	return 0
}

func (c *getInfoCommand) parseFlags(args []string) error {
	fs := flag.NewFlagSet("debug getinfo", flag.ContinueOnError)
	fs.SetOutput(c.env.Stderr)
	c.addOSFlags(fs)
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, prettyPrintGetInfo)
	return fs.Parse(args)
}

func (c *getInfoCommand) run() error {
	addr, err := c.getAddr()
	if err != nil {
		return err
	}
	target, err := util.GetTargetName(addr)
	if err != nil {
		return err
	}
	conn, err := util.NewGRPCClient(target)
	if err != nil {
		return err
	}
	defer conn.Close()

	debugClient := debugv1.NewDebugClient(conn)
	resp, err := debugClient.GetInfo(context.Background(), &debugv1.GetInfoRequest{})
	if err != nil {
		return err
	}

	return c.printer.PrintProto(resp)
}

func prettyPrintGetInfo(env *commoncli.Env, results ...any) error {
	resp, ok := results[0].(*debugv1.GetInfoResponse)
	if !ok {
		return errors.New("internal error: cli printer; please report this bug")
	}

	env.Printf("Agent Debug Info:\n")
	env.Printf("  Uptime:                          %s\n", (time.Duration(resp.Uptime) * time.Second).String())
	env.Printf("  Last Sync Success:               %s\n", time.Unix(resp.LastSyncSuccess, 0).UTC().Format(time.RFC3339))
	env.Printf("  Cached X.509 SVIDs:              %d\n", resp.CachedX509SvidsCount)
	env.Printf("  Cached JWT SVIDs:                %d\n", resp.CachedJwtSvidsCount)
	env.Printf("  Cached SVID Store X.509 SVIDs:   %d\n", resp.CachedSvidstoreX509SvidsCount)

	if len(resp.SvidChain) > 0 {
		env.Printf("  SVID Chain:\n")
		for i, cert := range resp.SvidChain {
			env.Printf("    [%d] SPIFFE ID:  %s\n", i, spiffeIDString(cert))
			env.Printf("        Subject:    %s\n", cert.Subject)
			env.Printf("        Expires At: %s\n", time.Unix(cert.ExpiresAt, 0).UTC().Format(time.RFC3339))
		}
	}

	return nil
}

func spiffeIDString(cert *debugv1.GetInfoResponse_Cert) string {
	if cert.Id == nil {
		return "(none)"
	}
	return fmt.Sprintf("spiffe://%s%s", cert.Id.TrustDomain, cert.Id.Path)
}
