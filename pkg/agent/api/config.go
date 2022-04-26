package api

import (
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	attestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/common/peertracker"
)

type Config struct {
	BindAddr net.Addr

	Manager manager.Manager

	Log logrus.FieldLogger

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
