package main

import (
	"net/http"
	"time"
)

const (
	ThresholdMultiplicator = 5
	ThresholdMinTime       = time.Minute * 3
)

type HealthChecksHandler struct {
	source       JWKSSource
	healthChecks HealthChecksConfig
	jwkThreshold time.Duration
	initTime     time.Time

	http.Handler
}

func NewHealthChecksHandler(source JWKSSource, config *Config) *HealthChecksHandler {
	h := &HealthChecksHandler{
		source:       source,
		healthChecks: *config.HealthChecks,
		jwkThreshold: jwkThreshold(config),
		initTime:     time.Now(),
	}

	mux := http.NewServeMux()
	mux.Handle(h.healthChecks.ReadyPath, http.HandlerFunc(h.readyCheck))
	mux.Handle(h.healthChecks.LivePath, http.HandlerFunc(h.liveCheck))

	h.Handler = mux
	return h
}

// jwkThreshold determines the duration from the last successful poll before the server is considered unhealthy
func jwkThreshold(config *Config) time.Duration {
	var duration time.Duration
	switch {
	case config.ServerAPI != nil:
		duration = config.ServerAPI.PollInterval
	case config.WorkloadAPI != nil:
		duration = config.WorkloadAPI.PollInterval
	default:
		duration = config.File.PollInterval
	}
	if duration*ThresholdMultiplicator < ThresholdMinTime {
		duration = ThresholdMinTime
	}
	return duration
}

// readyCheck is a health check that returns 200 if the server can successfully fetch a jwt keyset
func (h *HealthChecksHandler) readyCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	statusCode := http.StatusOK
	lastPoll := h.source.LastSuccessfulPoll()
	elapsed := time.Since(lastPoll)
	isReady := !lastPoll.IsZero() && elapsed < h.jwkThreshold

	if !isReady {
		statusCode = http.StatusInternalServerError
	}
	w.WriteHeader(statusCode)
}

// liveCheck is a health check that returns 200 if the server is able to reply to http requests
func (h *HealthChecksHandler) liveCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	statusCode := http.StatusOK
	lastPoll := h.source.LastSuccessfulPoll()
	elapsed := time.Since(lastPoll)
	isReady := !lastPoll.IsZero() && elapsed < h.jwkThreshold

	if lastPoll.IsZero() {
		elapsed := time.Since(h.initTime)
		if elapsed >= h.jwkThreshold {
			statusCode = http.StatusInternalServerError
		}
	} else if !isReady {
		statusCode = http.StatusInternalServerError
	}
	w.WriteHeader(statusCode)
}
