package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/gorilla/handlers"
)

type Handler struct {
	domain              string
	source              JWKSSource
	allowInsecureScheme bool

	http.Handler
}

func NewHandler(domain string, source JWKSSource, allowInsecureScheme bool) *Handler {
	h := &Handler{
		domain:              domain,
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
	if h.allowInsecureScheme {
		if r.URL.Scheme == "" {
			if r.TLS == nil {
				r.URL.Scheme = "http"
			} else {
				r.URL.Scheme = "https"
			}
		}
	} else {
		r.URL.Scheme = "https"
	}

	issuerURL := url.URL{
		Scheme: r.URL.Scheme,
		Host:   r.Host,
	}

	jwksURI := url.URL{
		Scheme: r.URL.Scheme,
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
