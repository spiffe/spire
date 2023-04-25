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

type purgeCommand struct {
	env        *commoncli.Env
	expiredFor time.Duration
	dryRun     bool
	printer    cliprinter.Printer
}

func NewPurgeCommand() cli.Command {
	return NewPurgeCommandWithEnv(commoncli.DefaultEnv)
}

func NewPurgeCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &purgeCommand{env: env})
}

func (*purgeCommand) Name() string {
	return "agent purge"
}

func (*purgeCommand) Synopsis() string {
	return "Purge expired agents that were attested using a non-TOFU security model based on a given time"
}

func (c *purgeCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) (err error) {
	agentClient := serverClient.NewAgentClient()
	resp, err := agentClient.ListAgents(ctx, &agentv1.ListAgentsRequest{
		Filter:     &agentv1.ListAgentsRequest_Filter{ByCanReattest: wrapperspb.Bool(true)},
		OutputMask: &types.AgentMask{X509SvidExpiresAt: true},
	})
	if err != nil {
		return fmt.Errorf("failed to list agents: %w", err)
	}

	agents := resp.GetAgents()
	expiredAgents := &expiredAgents{Agents: []*expiredAgent{}}

	for _, agent := range agents {
		id, err := idutil.IDFromProto(agent.Id)
		if err != nil {
			return err
		}

		expirationTime := time.Unix(agent.X509SvidExpiresAt, 0)

		if time.Since(expirationTime) > c.expiredFor {
			result := &expiredAgent{AgentID: id}

			if !c.dryRun {
				if _, err := agentClient.DeleteAgent(ctx, &agentv1.DeleteAgentRequest{Id: agent.Id}); err != nil {
					result.Error = err.Error()
				} else {
					result.Deleted = true
				}
			}
			expiredAgents.Agents = append(expiredAgents.Agents, result)
		}
	}

	return c.printer.PrintStruct(expiredAgents)
}

func (c *purgeCommand) AppendFlags(fs *flag.FlagSet) {
	fs.DurationVar(&c.expiredFor, "expiredFor", 30*24*time.Hour, "Amount of time that has passed since the agent's SVID has expired. It is used to determine which agents to purge.")
	fs.BoolVar(&c.dryRun, "dryRun", false, "Indicates that the command will not perform any action, but will print the agents that would be purged.")

	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, c.prettyPrintPurgeResult)
}

type expiredAgents struct {
	Agents []*expiredAgent `json:"expired_agents"`
}

type expiredAgent struct {
	AgentID spiffeid.ID `json:"agent_id"`
	Deleted bool        `json:"deleted"`
	Error   string      `json:"error,omitempty"`
}

func (c *purgeCommand) prettyPrintPurgeResult(env *commoncli.Env, results ...interface{}) error {
	if expAgents, ok := results[0].([]interface{})[0].(*expiredAgents); ok {
		if len(expAgents.Agents) == 0 {
			env.Println("No agents to purge.")
			return nil
		}

		msg := fmt.Sprintf("Found %d expired ", len(expAgents.Agents))
		msg = util.Pluralizer(msg, "agent", "agents", len(expAgents.Agents))
		env.Printf("%s\n\n", msg)

		if c.dryRun {
			env.Println("\nAgents that can be purged:")
			for _, result := range expAgents.Agents {
				env.Printf("SPIFFE ID         : %s\n", result.AgentID.String())
			}
			return nil
		}

		var agentsNotPurged []*expiredAgent
		var agentsPurged []*expiredAgent

		for _, result := range expAgents.Agents {
			if result.Deleted {
				agentsPurged = append(agentsPurged, result)
			} else {
				agentsNotPurged = append(agentsNotPurged, result)
			}
		}

		if len(agentsPurged) > 0 {
			c.printAgentsPurged(agentsPurged)
		}

		if len(agentsNotPurged) > 0 {
			c.printAgentsNotPurged(agentsNotPurged)
		}

		return nil
	}
	return cliprinter.ErrInternalCustomPrettyFunc
}

func (c *purgeCommand) printAgentsNotPurged(agentsNotPurged []*expiredAgent) {
	c.env.Println("Agents not purged:")
	for _, result := range agentsNotPurged {
		c.env.Printf("SPIFFE ID         : %s\n", result.AgentID.String())
		c.env.Printf("Error             : %s\n", result.Error)
	}
}

func (c *purgeCommand) printAgentsPurged(agentsPurged []*expiredAgent) {
	c.env.Println("Agents purged:")
	for _, result := range agentsPurged {
		c.env.Printf("SPIFFE ID         : %s\n", result.AgentID.String())
	}
}
