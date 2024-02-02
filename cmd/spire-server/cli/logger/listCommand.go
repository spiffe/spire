package logger

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	api "github.com/spiffe/spire-api-sdk/proto/spire/api/server/logger/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

const PAGE_SIZE = 500

type listCommand struct {
	env               *commoncli.Env
	printer           cliprinter.Printer
	serverClient      util.ServerClient

	requestRoot       string
	includeSubloggers bool
	pageSize          int32
}

// Returns a cli.command that lists all of the named loggers
func NewListCommand() cli.Command {
	return NewListCommandWithEnv(commoncli.DefaultEnv)
}

func NewListCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &listCommand{env: env})
}

func (_ *listCommand) Name() string {
	return "logger list"
}

func (_ *listCommand) Synopsis() string {
	return "Lists loggers and their log levels"
}

func (c *listCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	c.serverClient = serverClient

	var err error // predeclare for post loop error processing
	response := &api.ListLoggersResponse{}
	for page, err := c.pageRequest(ctx, "");
            err != nil && page.NextPageToken != "";
            page, err = c.pageRequest(ctx, page.NextPageToken) {
		response.Loggers = append(response.Loggers, page.Loggers...)
	}
	if err != nil {
		return fmt.Errorf("error fetching loggers: %w", err)
	}

	return nil
}

// Requests just one page.
func (c *listCommand) pageRequest(ctx context.Context, pageToken string) (*api.ListLoggersResponse, error) {
	return c.serverClient.NewLoggerClient().ListLoggers(ctx, &api.ListLoggersRequest{
		RootName: c.requestRoot,
		WithSubloggers: c.includeSubloggers,
		PageSize: c.pageSize,
		PageToken: pageToken,
	})
}

func (c *listCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.requestRoot, "name", "", 
		"The name of the logger (\"\" for root)")
	fs.BoolVar(&c.includeSubloggers, "subloggers", true, 
		"Include subloggers of \"name\"")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, c.prettyPrintLoggers)
}

func (l* listCommand) prettyPrintLoggers(env *commoncli.Env, results ...any) error {
	response, ok := results[0].(*api.ListLoggersResponse)
	if !ok {
		return errors.New("internal error: print list cli printer; please report this bug")
	}

	count := len(response.Loggers)
	switch count {
	case 0:
		if err := env.Printf("No loggers found\n"); err != nil {
			return err
		}
	case 1:
		if err := env.Printf("Found 1 logger\n"); err != nil {
			return err
		}
	default:
		if err := env.Printf("Found %d loggers\n", count); err != nil {
			return err
		}
		if err := env.Println(); err != nil {
			return err
		}
		for _, logger := range response.Loggers {
			if err := l.printLogger(env, logger); err != nil {
				return err
			}
		}
        }
	return nil
}

func (l *listCommand) printLogger(env *commoncli.Env, logger *types.Logger) error {
	if err := env.Printf("Logger Name  : %s\n", logger.Name); err != nil {
		return err
	}
	if err := env.Printf("Logger Level : %d\n", logger.CurrentLevel); err != nil {
		return err
	}
	if err := env.Printf("Logger Default : %d\n", logger.DefaultLevel); err != nil {
		return err
	}
	if err := env.Println(); err != nil {
		return err
	}
	return nil
}
