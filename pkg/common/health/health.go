package health

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/InVisionApp/go-health"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"google.golang.org/grpc"
)

const (
	// testDialTimeout is the duration to wait for a test dial
	testDialTimeout = 30 * time.Second

	readyCheckInterval = time.Minute
)

// State is the health state of a subsystem.
type State struct {
	// Live is whether or not the subsystem is live (i.e. in a good state
	// or in a state it can recover from while remaining alive). Global
	// liveness is only reported true if all subsystems report live.
	Live bool

	// Ready is whether or not the subsystem is ready (i.e. ready to perform
	// its function). Global readiness is only reported true if all subsystems
	// report ready.
	Ready bool

	// Subsystems can return whatever details they want here as long as it is
	// serializable via json.Marshal.
	// LiveDetails are opaque details related to the live check.
	LiveDetails interface{}

	// ReadyDetails are opaque details related to the live check.
	ReadyDetails interface{}
}

// Checkable is the interface implemented by subsystems that the checker uses
// to determine subsystem health.
type Checkable interface {
	CheckHealth() State
}

// Checker is responsible for running health checks and serving the healthcheck HTTP paths
type Checker interface {
	AddCheck(name string, checkable Checkable) error
	ReadyState() (bool, interface{})
	LiveState() (bool, interface{})
}

type ServableChecker interface {
	Checker
	ListenAndServe(ctx context.Context) error
}

func NewChecker(config Config, log logrus.FieldLogger) ServableChecker {
	hc := health.New()

	l := log.WithField(telemetry.SubsystemName, "health")
	hc.StatusListener = &statusListener{log: l}
	hc.Logger = &logadapter{FieldLogger: l}

	c := &checker{config: config, hc: hc, log: l}

	// Start HTTP server if ListenerEnabled is true
	if config.ListenerEnabled {
		handler := http.NewServeMux()

		handler.HandleFunc(config.getReadyPath(), c.readyHandler)
		handler.HandleFunc(config.getLivePath(), c.liveHandler)

		c.server = &http.Server{
			Addr:    config.getAddress(),
			Handler: handler,
		}
	}

	return c
}

type checker struct {
	config Config

	server *http.Server

	hc    *health.Health
	mutex sync.Mutex // Mutex protects non-threadsafe hc

	log logrus.FieldLogger
}

func (c *checker) AddCheck(name string, checkable Checkable) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.hc.AddCheck(&health.Config{
		Name:     name,
		Checker:  checkableWrapper{checkable: checkable},
		Interval: readyCheckInterval,
		Fatal:    true,
	})
}

func (c *checker) ListenAndServe(ctx context.Context) error {
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
			c.server.Close()
		}
	}()

	wg.Wait()

	if err := c.hc.Stop(); err != nil {
		c.log.WithError(err).Warn("Error stopping health checks")
	}

	return nil
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

// LiveState returns the global live state and details.
func (c *checker) LiveState() (bool, interface{}) {
	states, _, _ := c.hc.State()
	live, _, details, _ := c.checkStates(states)

	return live, details
}

// ReadyState returns the global ready state and details.
func (c *checker) ReadyState() (bool, interface{}) {
	states, _, _ := c.hc.State()
	_, ready, _, details := c.checkStates(states)

	return ready, details
}

func (c *checker) checkStates(states map[string]health.State) (bool, bool, interface{}, interface{}) {
	isLive, isReady := true, true

	liveDetails := make(map[string]interface{})
	readyDetails := make(map[string]interface{})
	for subsystemName, subsystemState := range states {
		state := subsystemState.Details.(State)
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

func (c *checker) liveHandler(w http.ResponseWriter, req *http.Request) {
	live, details := c.LiveState()

	statusCode := http.StatusOK
	if !live {
		statusCode = http.StatusInternalServerError
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(details)
}

func (c *checker) readyHandler(w http.ResponseWriter, req *http.Request) {
	ready, details := c.ReadyState()

	statusCode := http.StatusOK
	if !ready {
		statusCode = http.StatusInternalServerError
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(details)
}

// checkableWrapper wraps Checkable in something that conforms to health.ICheckable
type checkableWrapper struct {
	checkable Checkable
}

func (c checkableWrapper) Status() (interface{}, error) {
	state := c.checkable.CheckHealth()
	var err error
	switch {
	case state.Ready && state.Live:
	case state.Ready && !state.Live:
		err = errors.New("subsystem is not live")
	case !state.Ready && state.Live:
		err = errors.New("subsystem is not ready")
	case !state.Ready && !state.Live:
		err = errors.New("subsystem is not live or ready")
	}
	return state, err
}
