package agent

import (
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/mitchellh/cli"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"

	"golang.org/x/net/context"
)

type listCommand struct {
	// Type and value are delimited by a colon (:)
	// ex. "unix:uid:1000" or "spiffe_id:spiffe://example.org/foo"
	selectors common_cli.StringsFlag

	// Match used when filtering agents by selectors
	matchSelectorsOn string
}

// NewListCommand creates a new "list" subcommand for "agent" command.
func NewListCommand() cli.Command {
	return NewListCommandWithEnv(common_cli.DefaultEnv)
}

// NewListCommandWithEnv creates a new "list" subcommand for "agent" command
// using the environment specified
func NewListCommandWithEnv(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(listCommand))
}

func (*listCommand) Name() string {
	return "agent list"
}

func (listCommand) Synopsis() string {
	return "Lists attested agents and their SPIFFE IDs"
}

// Run lists attested agents
func (c *listCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
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

	agentClient := serverClient.NewAgentClient()

	pageToken := ""
	var agents []*types.Agent
	for {
		listResponse, err := agentClient.ListAgents(ctx, &agentv1.ListAgentsRequest{
			PageSize:  1000, // comfortably under the (4 MB/theoretical maximum size of 1 agent in MB)
			PageToken: pageToken,
			Filter:    filter,
		})
		if err != nil {
			return err
		}
		agents = append(agents, listResponse.Agents...)
		if pageToken = listResponse.NextPageToken; pageToken == "" {
			break
		}
	}

	if len(agents) == 0 {
		return env.Printf("No attested agents found\n")
	}

	msg := fmt.Sprintf("Found %d attested ", len(agents))
	msg = util.Pluralizer(msg, "agent", "agents", len(agents))
	env.Printf(msg + ":\n\n")

	return printAgents(env, agents...)
}

func (c *listCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.matchSelectorsOn, "matchSelectorsOn", "superset", "The match mode used when filtering by selectors. Options: exact, any, superset and subset")
	fs.Var(&c.selectors, "selector", "A colon-delimited type:value selector. Can be used more than once")
}

func printAgents(env *common_cli.Env, agents ...*types.Agent) error {
	for _, agent := range agents {
		id, err := spiffeid.New(agent.Id.TrustDomain, agent.Id.Path)
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
