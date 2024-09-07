package cli

import (
	"context"
	stdlog "log"
	"os"
	"strings"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-server/cli/agent"
	"github.com/spiffe/spire/cmd/spire-server/cli/bundle"
	"github.com/spiffe/spire/cmd/spire-server/cli/entry"
	"github.com/spiffe/spire/cmd/spire-server/cli/federation"
	"github.com/spiffe/spire/cmd/spire-server/cli/healthcheck"
	"github.com/spiffe/spire/cmd/spire-server/cli/jwt"
	localauthority_jwt "github.com/spiffe/spire/cmd/spire-server/cli/localauthority/jwt"
	localauthority_x509 "github.com/spiffe/spire/cmd/spire-server/cli/localauthority/x509"
	"github.com/spiffe/spire/cmd/spire-server/cli/logger"
	"github.com/spiffe/spire/cmd/spire-server/cli/run"
	"github.com/spiffe/spire/cmd/spire-server/cli/token"
	"github.com/spiffe/spire/cmd/spire-server/cli/validate"
	"github.com/spiffe/spire/cmd/spire-server/cli/x509"
	"github.com/spiffe/spire/pkg/common/fflag"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/common/version"
)

// CLI defines the server CLI configuration.
type CLI struct {
	LogOptions         []log.Option
	AllowUnknownConfig bool
}

// Run configures the server CLI commands and subcommands.
func (cc *CLI) Run(ctx context.Context, args []string) int {
	c := cli.NewCLI("spire-server", version.Version())
	c.Args = args
	c.Commands = map[string]cli.CommandFactory{
		"agent ban": func() (cli.Command, error) {
			return agent.NewBanCommand(), nil
		},
		"agent count": func() (cli.Command, error) {
			return agent.NewCountCommand(), nil
		},
		"agent evict": func() (cli.Command, error) {
			return agent.NewEvictCommand(), nil
		},
		"agent list": func() (cli.Command, error) {
			return agent.NewListCommand(), nil
		},
		"agent show": func() (cli.Command, error) {
			return agent.NewShowCommand(), nil
		},
		"agent purge": func() (cli.Command, error) {
			return agent.NewPurgeCommand(), nil
		},
		"bundle count": func() (cli.Command, error) {
			return bundle.NewCountCommand(), nil
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
		"entry count": func() (cli.Command, error) {
			return entry.NewCountCommand(), nil
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
		"federation create": func() (cli.Command, error) {
			return federation.NewCreateCommand(), nil
		},
		"federation delete": func() (cli.Command, error) {
			return federation.NewDeleteCommand(), nil
		},
		"federation list": func() (cli.Command, error) {
			return federation.NewListCommand(), nil
		},
		"federation show": func() (cli.Command, error) {
			return federation.NewShowCommand(), nil
		},
		"federation refresh": func() (cli.Command, error) {
			return federation.NewRefreshCommand(), nil
		},
		"federation update": func() (cli.Command, error) {
			return federation.NewUpdateCommand(), nil
		},
		"logger get": func() (cli.Command, error) {
			return logger.NewGetCommand(), nil
		},
		"logger set": func() (cli.Command, error) {
			return logger.NewSetCommand(), nil
		},
		"logger reset": func() (cli.Command, error) {
			return logger.NewResetCommand(), nil
		},
		"run": func() (cli.Command, error) {
			return run.NewRunCommand(ctx, cc.LogOptions, cc.AllowUnknownConfig), nil
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

	// TODO: Remove this when the forced_rotation feature flag is no longer
	// needed. Refer to https://github.com/spiffe/spire/issues/5398.
	addCommandsEnabledByFFlags(c.Commands)

	exitStatus, err := c.Run()
	if err != nil {
		stdlog.Println(err)
	}
	return exitStatus
}

// addCommandsEnabledByFFlags adds commands that are currently available only
// through a feature flag.
// Feature flags support through the fflag package in SPIRE Server is
// designed to work only with the run command and the config file.
// Since feature flags are intended to be used by developers of a specific
// feature only, exposing them through command line arguments is not
// convenient. Instead, we use the SPIRE_SERVER_FFLAGS environment variable
// to read the configured SPIRE Server feature flags from the environment
// when other commands may be enabled through feature flags.
func addCommandsEnabledByFFlags(commands map[string]cli.CommandFactory) {
	fflagsEnv := os.Getenv("SPIRE_SERVER_FFLAGS")
	fflags := strings.Split(fflagsEnv, " ")
	flagForcedRotationFound := false
	for _, ff := range fflags {
		if ff == string(fflag.FlagForcedRotation) {
			flagForcedRotationFound = true
			break
		}
	}

	if flagForcedRotationFound {
		commands["localauthority x509 show"] = func() (cli.Command, error) {
			return localauthority_x509.NewX509ShowCommand(), nil
		}
		commands["localauthority jwt show"] = func() (cli.Command, error) {
			return localauthority_jwt.NewJWTShowCommand(), nil
		}
	}
}
