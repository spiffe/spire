package health

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// testDialTimeout is the duration to wait for a test dial
	testDialTimeout = 30 * time.Second

	readyCheckInterval = time.Minute
)

// State is the health state of a subsystem.
type State struct {
	// Live is whether the subsystem is live (i.e. in a good state
	// or in a state it can recover from while remaining alive). Global
	// liveness is only reported true if all subsystems report live.
	Live bool

	// Ready is whether the subsystem is ready (i.e. ready to perform
	// its function). Global readiness is only reported true if all subsystems
	// report ready.
	Ready bool

	// Subsystems can return whatever details they want here as long as it is
	// serializable via json.Marshal.
	// LiveDetails are opaque details related to the live check.
	LiveDetails any

	// ReadyDetails are opaque details related to the live check.
	ReadyDetails any
}

// Checkable is the interface implemented by subsystems that the checker uses
// to determine subsystem health.
type Checkable interface {
	CheckHealth() State
}

// Checker is responsible for running health checks and serving the healthcheck HTTP paths
type Checker interface {
	AddCheck(name string, checkable Checkable) error
}

type ServableChecker interface {
	Checker
	ListenAndServe(ctx context.Context) error
}

func NewChecker(config Config, log logrus.FieldLogger) ServableChecker {
	l := log.WithField(telemetry.SubsystemName, "health")

	c := &checker{
		config: config,
		log:    l,

		cache: newCache(l, clock.New()),
	}

	// Start HTTP server if ListenerEnabled is true
	if config.ListenerEnabled {
		handler := http.NewServeMux()

		handler.HandleFunc(config.getReadyPath(), c.readyHandler)
		handler.HandleFunc(config.getLivePath(), c.liveHandler)

		c.server = &http.Server{
			Addr:              config.getAddress(),
			Handler:           handler,
			ReadHeaderTimeout: time.Second * 10,
		}
	}

	return c
}

type checker struct {
	config Config

	server *http.Server

	mutex sync.Mutex // Mutex protects non-threadsafe

	log   logrus.FieldLogger
	cache *cache
}

func (c *checker) AddCheck(name string, checkable Checkable) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.cache.addCheck(name, checkable)
}

func (c *checker) ListenAndServe(ctx context.Context) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if err := c.cache.start(ctx); err != nil {
		return err
	}

	var wg sync.WaitGroup
	if c.config.ListenerEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.log.WithField("address", c.server.Addr).Info("Serving health checks")
			if err := c.server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				c.log.WithError(err).Warn("Error serving health checks")
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		if c.server != nil {
			_ = c.server.Close()
		}
	}()

	wg.Wait()

	return nil
}

// WaitForTestDial tries to create a client connection to the given target
// with a blocking dial and a timeout specified in testDialTimeout.
// Nothing is done with the connection, which is just closed in case it
// is created.
func WaitForTestDial(ctx context.Context, addr net.Addr) {
	ctx, cancel := context.WithTimeout(ctx, testDialTimeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, //nolint: staticcheck // It is going to be resolved on #5152
		addr.String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, name string) (net.Conn, error) {
			return net.DialUnix("unix", nil, &net.UnixAddr{
				Net:  "unix",
				Name: name,
			})
		}),
		grpc.WithBlock()) //nolint: staticcheck // It is going to be resolved on #5152
	if err != nil {
		return
	}

	_ = conn.Close()
}

// LiveState returns the global live state and details.
func (c *checker) LiveState() (bool, any) {
	live, _, details, _ := c.checkStates()

	return live, details
}

// ReadyState returns the global ready state and details.
func (c *checker) ReadyState() (bool, any) {
	_, ready, _, details := c.checkStates()

	return ready, details
}

func (c *checker) checkStates() (bool, bool, any, any) {
	isLive, isReady := true, true

	liveDetails := make(map[string]any)
	readyDetails := make(map[string]any)
	for subsystemName, subsystemState := range c.cache.getStatuses() {
		state := subsystemState.details
		if !state.Live {
			isLive = false
		}

		if !state.Ready {
			isReady = false
		}

		liveDetails[subsystemName] = state.LiveDetails
		readyDetails[subsystemName] = state.ReadyDetails
	}

	return isLive, isReady, liveDetails, readyDetails
}

func (c *checker) liveHandler(w http.ResponseWriter, _ *http.Request) {
	live, details := c.LiveState()

	statusCode := http.StatusOK
	if !live {
		statusCode = http.StatusInternalServerError
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(details)
}

func (c *checker) readyHandler(w http.ResponseWriter, _ *http.Request) {
	ready, details := c.ReadyState()

	statusCode := http.StatusOK
	if !ready {
		statusCode = http.StatusInternalServerError
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(details)
}
