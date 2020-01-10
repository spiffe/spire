package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/api/node"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/peer"
)

const (
	AttestMsg = iota
	CSRMsg
	JSRMsg
)

type Limiter interface {
	Limit(ctx context.Context, msgType, count int) error
}

// Newlimiter returns a new node api rate.Limiter
func NewLimiter(l logrus.FieldLogger) Limiter {
	return newLimiter(l)
}

func newLimiter(l logrus.FieldLogger) *limiter {
	return &limiter{
		attestRate:   rate.Limit(node.AttestLimit),
		csrRate:      rate.Limit(node.CSRLimit),
		jsrRate:      rate.Limit(node.JSRLimit),
		lastNotified: make(map[string]time.Time),
		limiters:     make(map[int]map[string]*rate.Limiter),
		log:          l,
	}
}

type limiter struct {
	// Allowed number of messages per second
	attestRate rate.Limit
	csrRate    rate.Limit
	jsrRate    rate.Limit

	lastNotified map[string]time.Time
	limiters     map[int]map[string]*rate.Limiter
	log          logrus.FieldLogger
	mtx          sync.Mutex
}

// Limit enforces rate limiting policy by blocking until the specified number of messages can
// be processed. It introspects the context in order to identify the caller. An error will be
// returned if the context is cancelled, an invalid msgType is specified, or if the number
// of messages exceeds the burst limit.
func (l *limiter) Limit(ctx context.Context, msgType, count int) error {
	callerID, err := l.callerID(ctx)
	if err != nil {
		return err
	}

	rl, err := l.limiterFor(msgType, callerID)
	if err != nil {
		return err
	}

	res := rl.ReserveN(time.Now(), count)
	if res.Delay() > 0 {
		l.notify(callerID, msgType)
	}
	if !res.OK() {
		return errors.New("limiter: burst size exceeded")
	}

	// Ensure it is possible to complete requests if a deadline is set
	deadline, ok := ctx.Deadline()
	if ok && res.Delay() > time.Until(deadline) {
		res.Cancel()
		return errors.New("limiter: throttle delay exceeds deadline")
	}

	timer := time.NewTimer(res.Delay())
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		res.Cancel()
		return ctx.Err()
	}
}

func (l *limiter) limiterFor(msgType int, callerID string) (*rate.Limiter, error) {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	limiters := l.limitersFor(msgType)

	var err error
	rl, ok := limiters[callerID]
	if !ok {
		rl, err = l.newLimiterFor(msgType)
		if err != nil {
			return nil, err
		}

		limiters[callerID] = rl
	}

	return rl, nil
}

// A lock must be held on `l` before calling this function
func (l *limiter) limitersFor(msgType int) map[string]*rate.Limiter {
	limiters, ok := l.limiters[msgType]
	if !ok {
		limiters = make(map[string]*rate.Limiter)
		l.limiters[msgType] = limiters
	}

	return limiters
}

func (l *limiter) newLimiterFor(msgType int) (*rate.Limiter, error) {
	switch msgType {
	case AttestMsg:
		return rate.NewLimiter(l.attestRate, node.AttestLimit), nil
	case CSRMsg:
		return rate.NewLimiter(l.csrRate, node.CSRLimit), nil
	case JSRMsg:
		return rate.NewLimiter(l.jsrRate, node.JSRLimit), nil
	}

	return nil, fmt.Errorf("limiter: unknown message type %v", msgType)
}

func (l *limiter) callerID(ctx context.Context) (string, error) {
	limiterErr := errors.New("error applying rate limits")

	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil || p.Addr.Network() != "tcp" {
		l.log.Error("limiter: could not determine client address")
		return "", limiterErr
	}

	addr, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil || addr == "" {
		l.log.WithField(telemetry.Address, p.Addr.String()).Error("limiter: could not determine client ip from given address")
		return "", limiterErr
	}

	return addr, nil
}

func (l *limiter) notify(callerID string, msgType int) {
	l.mtx.Lock()
	if time.Since(l.lastNotified[callerID]) > 1*time.Hour {
		l.lastNotified[callerID] = time.Now()
		l.mtx.Unlock()
	} else {
		l.mtx.Unlock()
		return
	}

	var action string
	switch msgType {
	case AttestMsg:
		action = "perform attestation"
	case CSRMsg:
		action = "get certificates signed"
	case JSRMsg:
		action = "get JWTs signed"
	default:
		action = "do a questionable thing"
	}

	l.log.WithFields(logrus.Fields{
		telemetry.CallerID: callerID,
		telemetry.Action:   action,
	}).Info("caller is being ratelimited while attempting action")
}
