package api

import (
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	loggerv1 "github.com/spiffe/spire/pkg/agent/api/logger/v1"
	attestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

type Config struct {
	BindAddr net.Addr

	Manager manager.Manager

	Log logrus.FieldLogger

	// RootLog is the root logger for the entire process, used by the
	// Logger service to get/set/reset log levels at runtime.
	RootLog loggerv1.Logger

	Metrics telemetry.Metrics

	// Agent trust domain
	TrustDomain spiffeid.TrustDomain

	Uptime func() time.Duration

	Attestor attestor.Attestor

	AuthorizedDelegates []string
}

func New(c *Config) *Endpoints {
	return &Endpoints{
		c: c,
		listener: &peertracker.ListenerFactory{
			Log: c.Log,
		},
	}
}
