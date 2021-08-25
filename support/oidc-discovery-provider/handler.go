package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/url"

	"github.com/gorilla/handlers"
)

type Handler struct {
	source              JWKSSource
	domainPolicy        DomainPolicy
	allowInsecureScheme bool

	http.Handler
}

func NewHandler(domainPolicy DomainPolicy, source JWKSSource, allowInsecureScheme bool) *Handler {
	h := &Handler{
		domainPolicy:        domainPolicy,
		source:              source,
		allowInsecureScheme: allowInsecureScheme,
	}

	mux := http.NewServeMux()
	mux.Handle("/.well-known/openid-configuration", handlers.ProxyHeaders(http.HandlerFunc(h.serveWellKnown)))
	mux.Handle("/keys", http.HandlerFunc(h.serveKeys))

	h.Handler = mux
	return h
}

func (h *Handler) serveWellKnown(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := h.verifyHost(r.Host); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	urlScheme := "https"
	if h.allowInsecureScheme && r.TLS == nil && r.URL.Scheme != "https" {
		urlScheme = "http"
	}

	issuerURL := url.URL{
		Scheme: urlScheme,
		Host:   r.Host,
	}

	jwksURI := url.URL{
		Scheme: urlScheme,
		Host:   r.Host,
		Path:   "/keys",
	}

	doc := struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`

		// The following are required fields that we'll just hardcode response
		// to based on SPIRE capabilities, etc.
		AuthorizationEndpoint            string   `json:"authorization_endpoint"`
		ResponseTypesSupported           []string `json:"response_types_supported"`
		SubjectTypesSupported            []string `json:"subject_types_supported"`
		IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	}{
		Issuer:  issuerURL.String(),
		JWKSURI: jwksURI.String(),

		AuthorizationEndpoint:            "",
		ResponseTypesSupported:           []string{"id_token"},
		SubjectTypesSupported:            []string{},
		IDTokenSigningAlgValuesSupported: []string{"RS256", "ES256", "ES384"},
	}

	docBytes, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		http.Error(w, "failed to marshal document", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(docBytes)
}

func (h *Handler) serveKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	jwks, modTime, ok := h.source.FetchKeySet()
	if !ok {
		http.Error(w, "document not available", http.StatusInternalServerError)
		return
	}

	jwksBytes, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		http.Error(w, "failed to marshal JWKS", http.StatusInternalServerError)
		return
	}

	// Disable caching
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	w.Header().Set("Content-Type", "application/json")
	http.ServeContent(w, r, "keys", modTime, bytes.NewReader(jwksBytes))
}

func (h *Handler) verifyHost(host string) error {
	// Obtain the domain name from the host value, which comes from the
	// request, or is pulled from the X-Forwarded-Host header (via the
	// ProxyHeaders middleware). The value may be in host or host:port form.
	domain, _, err := net.SplitHostPort(host)
	if err != nil {
		// `Host` was not in the host:port form form.
		domain = host
	}
	return h.domainPolicy(domain)
}
