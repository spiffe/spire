package main

import (
	"net/http"
)

type HealthChecksHandler struct {
	source       JWKSSource
	healthChecks HealthChecksConfig

	http.Handler
}

func NewHealthChecksHandler(source JWKSSource, healthChecks HealthChecksConfig) *HealthChecksHandler {
	h := &HealthChecksHandler{
		source:       source,
		healthChecks: healthChecks,
	}

	mux := http.NewServeMux()
	mux.Handle(healthChecks.ReadyPath, http.HandlerFunc(h.readyCheck))
	mux.Handle(healthChecks.LivePath, http.HandlerFunc(h.liveCheck))

	h.Handler = mux
	return h
}

// readyCheck is a health check that returns 200 if the server is able to reply to http requests
func (h *HealthChecksHandler) readyCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// liveCheck is a health check that returns 200 if the server can successfully fetch a jwt keyset
func (h *HealthChecksHandler) liveCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	statusCode := http.StatusOK
	_, _, valid := h.source.FetchKeySet()
	if !valid {
		statusCode = http.StatusInternalServerError
	}
	w.WriteHeader(statusCode)
}
