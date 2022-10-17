package health

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

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
}

type ServableChecker interface {
	Checker
	ListenAndServe(ctx context.Context) error
}

func NewChecker(config Config, log logrus.FieldLogger) ServableChecker {
	l := log.WithField(telemetry.SubsystemName, "health")

	c := &checker{
		config:        config,
		log:           l,
		currentStatus: make(map[string]*CheckState),
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

	allowedChecks map[string]Checkable
	mutex         sync.Mutex // Mutex protects non-threadsafe

	currentStatus map[string]*CheckState
	statusMutex   sync.Mutex

	log logrus.FieldLogger
}

// TODO: AddChek no longer require an error
func (c *checker) AddCheck(name string, checkable Checkable) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.allowedChecks == nil {
		c.allowedChecks = make(map[string]Checkable)
	}

	c.allowedChecks[name] = checkable
	return nil
}

func (c *checker) ListenAndServe(ctx context.Context) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if err := c.startChecks(ctx); err != nil {
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

	return nil
}

// WaitForTestDial tries to create a client connection to the given target
// with a blocking dial and a timeout specified in testDialTimeout.
// Nothing is done with the connection, which is just closed in case it
// is created.
func WaitForTestDial(ctx context.Context, addr net.Addr) {
	ctx, cancel := context.WithTimeout(ctx, testDialTimeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx,
		addr.String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
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
	live, _, details, _ := c.checkStates()

	return live, details
}

// ReadyState returns the global ready state and details.
func (c *checker) ReadyState() (bool, interface{}) {
	_, ready, _, details := c.checkStates()

	return ready, details
}

func (c *checker) checkStates() (bool, bool, interface{}, interface{}) {
	isLive, isReady := true, true

	liveDetails := make(map[string]interface{})
	readyDetails := make(map[string]interface{})
	for subsystemName, subsystemState := range c.getAllStatus() {
		state := subsystemState.Details
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

func (c *checker) startChecks(ctx context.Context) error {
	if len(c.allowedChecks) < 1 {
		return errors.New("no health checks defined")
	}

	for name, check := range c.allowedChecks {
		c.startRunner(ctx, name, check)
	}
	return nil
}

func (c *checker) startRunner(ctx context.Context, name string, check Checkable) {
	log := c.log.WithField("name", name)
	log.Debug("Starting checker")

	checkFunc := func() {
		state, err := verifyStatus(check, log)

		checkState := &CheckState{
			Status:    "ok",
			Details:   state,
			CheckTime: time.Now(),
		}
		if err != nil {
			log.WithError(err).Error("healthcheck has failed")
			checkState.Err = err.Error()
			checkState.Status = "failed"
		}

		c.setStatus(name, checkState)
	}

	ticker := time.NewTicker(readyCheckInterval)

	go func() {
		defer func() {
			log.Debug("Checker exiting")
			ticker.Stop()
		}()
		for {
			checkFunc()

			select {
			case <-ticker.C:
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (c *checker) setStatus(name string, state *CheckState) {
	c.handleStatusListener(name, state)

	c.statusMutex.Lock()
	defer c.statusMutex.Unlock()

	c.currentStatus[name] = state
}

func (c *checker) handleStatusListener(name string, state *CheckState) {
	// get the previous state
	c.statusMutex.Lock()
	prevState := c.currentStatus[name]
	c.statusMutex.Unlock()

	// state is failure
	if state.Status == "failed" {
		if prevState == nil || prevState.Status == "ok" {
			// new failure: previous state was ok
			c.log.WithField("check", name).
				WithField("details", state.Details).
				WithField("error", state.Err).
				Warn("Health check failed")

				// TODO: add mock
			state.TimeOfFirstFailure = time.Now()
		} else {
			// carry the time of first failure from the previous state
			state.TimeOfFirstFailure = prevState.TimeOfFirstFailure
		}
		state.ContiguousFailures = prevState.ContiguousFailures + 1
	} else if prevState != nil && prevState.Status == "failed" {
		// recovery, previous state was failure
		failureSeconds := time.Now().Sub(prevState.TimeOfFirstFailure).Seconds()

		c.log.WithField("check", name).
			WithField("details", state.Details).
			WithField("error", state.Err).
			WithField("failures", prevState.ContiguousFailures).
			WithField("duration", failureSeconds).
			Info("Health check recovered")
	}
}

func (c *checker) getAllStatus() map[string]*CheckState {
	c.statusMutex.Lock()
	defer c.statusMutex.Unlock()

	return c.currentStatus
}

func verifyStatus(check Checkable, log logrus.FieldLogger) (State, error) {
	state := check.CheckHealth()
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

type CheckState struct {
	// Status of the health check state ("ok" or "failed")
	Status string

	// Err is the error returned from a failed health check
	Err string

	// Details contains more contextual detail about a
	// failing health check.
	Details State

	// CheckTime is the time of the last health check
	CheckTime time.Time

	ContiguousFailures int64     `json:"num_failures"`     // the number of failures that occurred in a row
	TimeOfFirstFailure time.Time `json:"first_failure_at"` // the time of the initial transitional failure for any given health check
}
