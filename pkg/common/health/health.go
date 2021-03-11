package health

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/InVisionApp/go-health"
	"github.com/InVisionApp/go-health/handlers"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"google.golang.org/grpc"
)

const (
	// testDialTimeout is the duration to wait for a test dial
	testDialTimeout = 30 * time.Second

	readyCheckInterval = time.Minute
)

// Checker is responsible for running health checks and serving the healthcheck HTTP paths
type Checker struct {
	config Config

	server *http.Server

	hc    *health.Health
	mutex sync.Mutex // Mutex protects non-threadsafe hc

	log logrus.FieldLogger
}

func live(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
}

func NewChecker(config Config, log logrus.FieldLogger) *Checker {
	hc := health.New()

	var server *http.Server
	// Start HTTP server if ListenerEnabled is true
	if config.ListenerEnabled {
		handler := http.NewServeMux()

		handler.HandleFunc(config.getReadyPath(), handlers.NewJSONHandlerFunc(hc, nil))
		handler.HandleFunc(config.getLivePath(), live)

		server = &http.Server{
			Addr:    config.getAddress(),
			Handler: handler,
		}
	}

	l := log.WithField(telemetry.SubsystemName, "health")
	hc.StatusListener = &statusListener{log: l}
	hc.Logger = &logadapter{FieldLogger: l}

	return &Checker{config: config, server: server, hc: hc, log: log}
}

// WaitForTestDial tries to create a client connection to the given target
// with a blocking dial and a timeout specified in testDialTimeout.
// Nothing is done with the connection, which is just closed in case it
// is created.
func WaitForTestDial(ctx context.Context, addr *net.UnixAddr) {
	ctx, cancel := context.WithTimeout(ctx, testDialTimeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx,
		addr.String(),
		grpc.WithInsecure(),
		grpc.WithContextDialer(func(ctx context.Context, name string) (net.Conn, error) {
			return net.DialUnix("unix", nil, &net.UnixAddr{
				Net:  "unix",
				Name: name,
			})
		}),
		grpc.WithBlock())
	if err != nil {
		return
	}

	conn.Close()
}

func (c *Checker) AddCheck(name string, checker health.ICheckable) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.hc.AddCheck(&health.Config{
		Name:     name,
		Checker:  checker,
		Interval: readyCheckInterval,
		Fatal:    true,
	})
}

func (c *Checker) ListenAndServe(ctx context.Context) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if err := c.hc.Start(); err != nil {
		return err
	}

	var wg sync.WaitGroup
	if c.config.ListenerEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.log.WithField("address", c.server.Addr).Info("Serving health checks")
			if err := c.server.ListenAndServe(); err != http.ErrServerClosed {
				c.log.WithError(err).Warn("Error serving health checks")
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		if c.server != nil {
			c.server.Close()
		}
	}()

	wg.Wait()

	if err := c.hc.Stop(); err != nil {
		c.log.WithError(err).Warn("Error stopping health checks")
	}

	return nil
}
