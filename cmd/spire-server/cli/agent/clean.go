package agent

import (
	"flag"
	"fmt"
	"time"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"github.com/spiffe/spire/pkg/common/idutil"
	"golang.org/x/net/context"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type cleanCommand struct {
	env          *commoncli.Env
	expiredSince time.Duration
	dryRun       bool
	printer      cliprinter.Printer
}

func NewCleanCommand() cli.Command {
	return NewCleanCommandWithEnv(commoncli.DefaultEnv)
}

func NewCleanCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &cleanCommand{env: env})
}

func (*cleanCommand) Name() string {
	return "agent clean"
}

func (*cleanCommand) Synopsis() string {
	return "Delete expired agents that attested using a non-TOFU security model based on a given time"
}

func (c *cleanCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	agentClient := serverClient.NewAgentClient()
	resp, err := agentClient.ListAgents(ctx, &agentv1.ListAgentsRequest{
		Filter:     &agentv1.ListAgentsRequest_Filter{ByCanReattest: wrapperspb.Bool(true)},
		OutputMask: &types.AgentMask{X509SvidExpiresAt: true},
	})
	if err != nil {
		return fmt.Errorf("failed to list agents: %w", err)
	}

	agents := resp.GetAgents()
	expiredAgents := &ExpiredAgents{Agents: []*ExpiredAgent{}}

	now := time.Now()

	for _, agent := range agents {
		id, err := idutil.IDFromProto(agent.Id)
		if err != nil {
			return err
		}

		expirationTime := time.Unix(agent.X509SvidExpiresAt, 0)

		if now.Sub(expirationTime) > c.expiredSince {
			result := &ExpiredAgent{AgentID: id}

			if !c.dryRun {
				if _, err := agentClient.DeleteAgent(ctx, &agentv1.DeleteAgentRequest{Id: agent.Id}); err == nil {
					result.Deleted = true
				}
			}
			expiredAgents.Agents = append(expiredAgents.Agents, result)
		}
	}

	return c.printer.PrintStruct(expiredAgents)
}

func (c *cleanCommand) AppendFlags(fs *flag.FlagSet) {
	fs.DurationVar(&c.expiredSince, "expiredSince", 0, "Specifies the time range for the expired agents to be deleted; defaults to current time.")
	fs.BoolVar(&c.dryRun, "dryRun", false, "Indicates that the command will not perform any action, but will print the agents that would be purged.")

	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, c.prettyPrintPurgeResult)
}

type ExpiredAgents struct {
	Agents []*ExpiredAgent `json:"expired_agents"`
}

type ExpiredAgent struct {
	AgentID spiffeid.ID `json:"agent_id"`
	Deleted bool        `json:"deleted"`
}

func (c *cleanCommand) prettyPrintPurgeResult(env *commoncli.Env, results ...interface{}) error {
	if expiredAgents, ok := results[0].([]interface{})[0].(*ExpiredAgents); ok {
		if len(expiredAgents.Agents) == 0 {
			env.Println("No agents to purge.")
			return nil
		}

		msg := fmt.Sprintf("Found %d expired ", len(expiredAgents.Agents))
		msg = util.Pluralizer(msg, "agent", "agents", len(expiredAgents.Agents))
		env.Printf("%s\n\n", msg)

		if !c.dryRun {
			env.Println("Agents purged:")
		}
		agentsNotPurged := []*ExpiredAgent{}

		for _, result := range expiredAgents.Agents {
			if result.Deleted {
				env.Printf("SPIFFE ID         : %s\n", result.AgentID.String())
			} else {
				agentsNotPurged = append(agentsNotPurged, result)
			}
		}

		if len(agentsNotPurged) > 0 {
			if !c.dryRun {
				env.Println("\nAgents not purged:")
			} else {
				env.Println("\nAgents that can be purged:")
			}
			for _, result := range agentsNotPurged {
				env.Printf("SPIFFE ID         : %s\n", result.AgentID.String())
			}
		}

		return nil
	}
	return cliprinter.ErrInternalCustomPrettyFunc
}
