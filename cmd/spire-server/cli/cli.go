package cli

import (
	stdlog "log"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-server/cli/agent"
	"github.com/spiffe/spire/cmd/spire-server/cli/bundle"
	"github.com/spiffe/spire/cmd/spire-server/cli/entry"
	"github.com/spiffe/spire/cmd/spire-server/cli/healthcheck"
	"github.com/spiffe/spire/cmd/spire-server/cli/jwt"
	"github.com/spiffe/spire/cmd/spire-server/cli/run"
	"github.com/spiffe/spire/cmd/spire-server/cli/token"
	"github.com/spiffe/spire/cmd/spire-server/cli/validate"
	"github.com/spiffe/spire/cmd/spire-server/cli/x509"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/common/version"
)

type CLI struct {
	LogOptions         []log.Option
	AllowUnknownConfig bool
}

func (cc *CLI) Run(args []string) int {
	c := cli.NewCLI("spire-server", version.Version())
	c.Args = args
	c.Commands = map[string]cli.CommandFactory{
		"agent evict": func() (cli.Command, error) {
			return agent.NewEvictCommand(), nil
		},
		"agent list": func() (cli.Command, error) {
			return agent.NewListCommand(), nil
		},
		"agent show": func() (cli.Command, error) {
			return agent.NewShowCommand(), nil
		},
		"bundle show": func() (cli.Command, error) {
			return bundle.NewShowCommand(), nil
		},
		"bundle list": func() (cli.Command, error) {
			return bundle.NewListCommand(), nil
		},
		"bundle set": func() (cli.Command, error) {
			return bundle.NewSetCommand(), nil
		},
		"bundle delete": func() (cli.Command, error) {
			return bundle.NewDeleteCommand(), nil
		},
		"entry create": func() (cli.Command, error) {
			return entry.NewCreateCommand(), nil
		},
		"entry update": func() (cli.Command, error) {
			return entry.NewUpdateCommand(), nil
		},
		"entry delete": func() (cli.Command, error) {
			return entry.NewDeleteCommand(), nil
		},
		"entry show": func() (cli.Command, error) {
			return entry.NewShowCommand(), nil
		},
		"run": func() (cli.Command, error) {
			return run.NewRunCommand(cc.LogOptions, cc.AllowUnknownConfig), nil
		},
		"token generate": func() (cli.Command, error) {
			return token.NewGenerateCommand(), nil
		},
		"healthcheck": func() (cli.Command, error) {
			return healthcheck.NewHealthCheckCommand(), nil
		},
		"x509 mint": func() (cli.Command, error) {
			return x509.NewMintCommand(), nil
		},
		"jwt mint": func() (cli.Command, error) {
			return jwt.NewMintCommand(), nil
		},
		"validate": func() (cli.Command, error) {
			return validate.NewValidateCommand(), nil
		},
	}

	exitStatus, err := c.Run()
	if err != nil {
		stdlog.Println(err)
	}
	return exitStatus
}
