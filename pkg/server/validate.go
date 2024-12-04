package server

import (
	"context"

	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/hostservice/agentstore"
	"github.com/spiffe/spire/pkg/server/hostservice/identityprovider"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
)

func (s *Server) ValidateConfig(ctx context.Context) (err error) {
	cat, err := catalog.ValidateConfig(ctx, catalog.Config{
		Log:              s.config.Log.WithField(telemetry.SubsystemName, telemetry.Catalog),
		Metrics:          fakemetrics.New(),
		TrustDomain:      s.config.TrustDomain,
		PluginConfigs:    s.config.PluginConfigs,
		IdentityProvider: identityprovider.New(identityprovider.Config{TrustDomain: s.config.TrustDomain}),
		AgentStore:       agentstore.New(),
		HealthChecker:    health.NewChecker(s.config.HealthChecks, s.config.Log),
	})
	if err != nil {
		return err
	}

	cat.Close()
	return err
}
