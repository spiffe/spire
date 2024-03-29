package agent

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/mitchellh/cli"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type countCommand struct {
	// Type and value are delimited by a colon (:)
	// ex. "unix:uid:1000" or "spiffe_id:spiffe://example.org/foo"
	selectors commoncli.StringsFlag

	// Match used when filtering by selectors
	matchSelectorsOn string

	// Filters agents to those that are banned.
	banned commoncli.BoolFlag

	// Filters agents by those expires before.
	expiresBefore string

	// Filters agents to those matching the attestation type.
	attestationType string

	// Filters agents that can re-attest.
	canReattest commoncli.BoolFlag

	env *commoncli.Env

	printer cliprinter.Printer
}

// NewCountCommand creates a new "count" subcommand for "agent" command.
func NewCountCommand() cli.Command {
	return NewCountCommandWithEnv(commoncli.DefaultEnv)
}

// NewCountCommandWithEnv creates a new "count" subcommand for "agent" command
// using the environment specified.
func NewCountCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &countCommand{env: env})
}

func (*countCommand) Name() string {
	return "agent count"
}

func (*countCommand) Synopsis() string {
	return "Count attested agents"
}

// Run counts attested agents
func (c *countCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	filter := &agentv1.CountAgentsRequest_Filter{}
	if len(c.selectors) > 0 {
		matchBehavior, err := parseToSelectorMatch(c.matchSelectorsOn)
		if err != nil {
			return err
		}

		selectors := make([]*types.Selector, len(c.selectors))
		for i, sel := range c.selectors {
			selector, err := util.ParseSelector(sel)
			if err != nil {
				return fmt.Errorf("error parsing selector %q: %w", sel, err)
			}
			selectors[i] = selector
		}
		filter.BySelectorMatch = &types.SelectorMatch{
			Selectors: selectors,
			Match:     matchBehavior,
		}
	}

	if c.expiresBefore != "" {
		// Parse the time string into a time.Time object
		_, err := time.Parse("2006-01-02 15:04:05 -0700 -07", c.expiresBefore)
		if err != nil {
			return fmt.Errorf("date is not valid: %w", err)
		}
		filter.ByExpiresBefore = c.expiresBefore
	}

	if c.attestationType != "" {
		filter.ByAttestationType = c.attestationType
	}

	// 0: all, 1: can't reattest, 2: can reattest
	if c.canReattest == 1 {
		filter.ByCanReattest = wrapperspb.Bool(false)
	}
	if c.canReattest == 2 {
		filter.ByCanReattest = wrapperspb.Bool(true)
	}

	// 0: all, 1: no-banned, 2: banned
	if c.banned == 1 {
		filter.ByBanned = wrapperspb.Bool(false)
	}
	if c.banned == 2 {
		filter.ByBanned = wrapperspb.Bool(true)
	}

	agentClient := serverClient.NewAgentClient()

	countResponse, err := agentClient.CountAgents(ctx, &agentv1.CountAgentsRequest{
		Filter: filter,
	})
	if err != nil {
		return err
	}

	return c.printer.PrintProto(countResponse)
}

func (c *countCommand) AppendFlags(fs *flag.FlagSet) {
	fs.Var(&c.selectors, "selector", "A colon-delimited type:value selector. Can be used more than once")
	fs.StringVar(&c.attestationType, "attestationType", "", "Filter by attestation type, like join_token or x509pop.")
	fs.Var(&c.canReattest, "canReattest", "Filter based on string received, 'true': agents that can reattest, 'false': agents that can't reattest, other value will return all.")
	fs.Var(&c.banned, "banned", "Filter based on string received, 'true': banned agents, 'false': not banned agents, other value will return all.")
	fs.StringVar(&c.expiresBefore, "expiresBefore", "", "Filter by expiration time (format: \"2006-01-02 15:04:05 -0700 -07\")")
	fs.StringVar(&c.matchSelectorsOn, "matchSelectorsOn", "superset", "The match mode used when filtering by selectors. Options: exact, any, superset and subset")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, prettyPrintCount)
}

func prettyPrintCount(env *commoncli.Env, results ...any) error {
	countResp, ok := results[0].(*agentv1.CountAgentsResponse)
	if !ok {
		return errors.New("internal error: cli printer; please report this bug")
	}
	count := int(countResp.Count)
	msg := fmt.Sprintf("%d attested ", count)
	msg = util.Pluralizer(msg, "agent", "agents", count)
	env.Println(msg)
	return nil
}
