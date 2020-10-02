package api

import (
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/common/peertracker"
)

type Config struct {
	BindAddr *net.UnixAddr

	Manager manager.Manager

	Log logrus.FieldLogger

	// Agent trust domain
	TrustDomain spiffeid.TrustDomain

	Uptime func() time.Duration
}

func New(c *Config) *Endpoints {
	return &Endpoints{
		c: c,
		unixListener: &peertracker.ListenerFactory{
			Log: c.Log,
		},
	}
}
