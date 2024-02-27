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
	"github.com/spiffe/spire/pkg/common/idutil"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type listCommand struct {
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

// NewListCommand creates a new "list" subcommand for "agent" command.
func NewListCommand() cli.Command {
	return NewListCommandWithEnv(commoncli.DefaultEnv)
}

// NewListCommandWithEnv creates a new "list" subcommand for "agent" command
// using the environment specified
func NewListCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &listCommand{env: env})
}

func (*listCommand) Name() string {
	return "agent list"
}

func (*listCommand) Synopsis() string {
	return "Lists attested agents and their SPIFFE IDs"
}

// Run lists attested agents
func (c *listCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	filter := &agentv1.ListAgentsRequest_Filter{}
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

	pageToken := ""
	response := new(agentv1.ListAgentsResponse)
	for {
		listResponse, err := agentClient.ListAgents(ctx, &agentv1.ListAgentsRequest{
			PageSize:  1000, // comfortably under the (4 MB/theoretical maximum size of 1 agent in MB)
			PageToken: pageToken,
			Filter:    filter,
		})
		if err != nil {
			return err
		}
		response.Agents = append(response.Agents, listResponse.Agents...)
		if pageToken = listResponse.NextPageToken; pageToken == "" {
			break
		}
	}

	return c.printer.PrintProto(response)
}

func (c *listCommand) AppendFlags(fs *flag.FlagSet) {
	fs.Var(&c.selectors, "selector", "A colon-delimited type:value selector. Can be used more than once")
	fs.StringVar(&c.attestationType, "attestationType", "", "Filter by attestation type, like join_token or x509pop.")
	fs.Var(&c.canReattest, "canReattest", "Filter based on string received, 'true': agents that can reattest, 'false': agents that can't reattest, other value will return all.")
	fs.Var(&c.banned, "banned", "Filter based on string received, 'true': banned agents, 'false': not banned agents, other value will return all.")
	fs.StringVar(&c.expiresBefore, "expiresBefore", "", "Filter by expiration time (format: \"2006-01-02 15:04:05 -0700 -07\")")
	fs.StringVar(&c.matchSelectorsOn, "matchSelectorsOn", "superset", "The match mode used when filtering by selectors. Options: exact, any, superset and subset")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, prettyPrintAgents)
}

func prettyPrintAgents(env *commoncli.Env, results ...any) error {
	listResp, ok := results[0].(*agentv1.ListAgentsResponse)
	if !ok {
		return errors.New("internal error: cli printer; please report this bug")
	}
	agents := listResp.Agents

	if len(agents) == 0 {
		return env.Printf("No attested agents found\n")
	}

	msg := fmt.Sprintf("Found %d attested ", len(agents))
	msg = util.Pluralizer(msg, "agent", "agents", len(agents))
	env.Printf("%s:\n\n", msg)
	return printAgents(env, agents...)
}

func printAgents(env *commoncli.Env, agents ...*types.Agent) error {
	for _, agent := range agents {
		id, err := idutil.IDFromProto(agent.Id)
		if err != nil {
			return err
		}

		if err := env.Printf("SPIFFE ID         : %s\n", id.String()); err != nil {
			return err
		}
		if err := env.Printf("Attestation type  : %s\n", agent.AttestationType); err != nil {
			return err
		}
		if err := env.Printf("Expiration time   : %s\n", time.Unix(agent.X509SvidExpiresAt, 0)); err != nil {
			return err
		}
		// Banned agents will have an empty serial number
		if agent.Banned {
			if err := env.Printf("Banned            : %t\n", agent.Banned); err != nil {
				return err
			}
		} else {
			if err := env.Printf("Serial number     : %s\n", agent.X509SvidSerialNumber); err != nil {
				return err
			}
		}
		if err := env.Printf("Can re-attest     : %t\n", agent.CanReattest); err != nil {
			return err
		}

		if err := env.Println(); err != nil {
			return err
		}
	}

	return nil
}

func parseToSelectorMatch(match string) (types.SelectorMatch_MatchBehavior, error) {
	switch match {
	case "exact":
		return types.SelectorMatch_MATCH_EXACT, nil
	case "any":
		return types.SelectorMatch_MATCH_ANY, nil
	case "superset":
		return types.SelectorMatch_MATCH_SUPERSET, nil
	case "subset":
		return types.SelectorMatch_MATCH_SUBSET, nil
	default:
		return types.SelectorMatch_MATCH_SUPERSET, errors.New("unsupported match behavior")
	}
}
