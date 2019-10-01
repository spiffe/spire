// Copyright (c) 2009 The Go Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Package acmetest provides types for testing acme and autocert packages.
//
// SPIRE modifications:
// - Verifies signatures on incoming requests to ensures requests are signed
//   appropriately with by the KeyManager.
// - Tracks accounts and implements the account endpoints (to facilitate
//   accepting terms-of-service)
// - Fails new-cert requests if the terms-of-service has not been accepted by
//   the account.

package acmetest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/square/go-jose.v2"
)

// CAServer is a simple test server which implements ACME spec bits needed for testing.
type CAServer struct {
	URL   string         // server URL after it has been started
	Roots *x509.CertPool // CA root certificates; initialized in NewCAServer

	rootKey      crypto.Signer
	rootCert     []byte // DER encoding
	rootTemplate *x509.Certificate

	server           *httptest.Server
	challengeTypes   []string // supported challenge types
	domainsWhitelist []string // only these domains are valid for issuing, unless empty

	mu             sync.Mutex
	certCount      int                       // number of issued certs
	domainAddr     map[string]string         // domain name to addr:port resolution
	authorizations map[string]*authorization // keyed by domain name
	errors         []error                   // encountered client errors
	accounts       map[string]*account       // accounts keyed by public key
}

// NewCAServer creates a new ACME test server and starts serving requests.
// The returned CAServer issues certs signed with the CA roots
// available in the Roots field.
//
// The challengeTypes argument defines the supported ACME challenge types
// sent to a client in a response for a domain authorization.
// If domainsWhitelist is non-empty, the certs will be issued only for the specified
// list of domains. Otherwise, any domain name is allowed.
func NewCAServer(challengeTypes []string, domainsWhitelist []string) *CAServer {
	var whitelist []string
	whitelist = append(whitelist, domainsWhitelist...)
	sort.Strings(whitelist)
	ca := &CAServer{
		challengeTypes:   challengeTypes,
		domainsWhitelist: whitelist,
		domainAddr:       make(map[string]string),
		authorizations:   make(map[string]*authorization),
		accounts:         make(map[string]*account),
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("ecdsa.GenerateKey: %v", err))
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Acme Co"},
			CommonName:   "Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(fmt.Sprintf("x509.CreateCertificate: %v", err))
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(fmt.Sprintf("x509.ParseCertificate: %v", err))
	}
	ca.Roots = x509.NewCertPool()
	ca.Roots.AddCert(cert)
	ca.rootKey = key
	ca.rootCert = der
	ca.rootTemplate = tmpl

	ca.server = httptest.NewServer(http.HandlerFunc(ca.handle))
	ca.URL = ca.server.URL
	return ca
}

// Close shuts down the server and blocks until all outstanding
// requests on this server have completed.
func (ca *CAServer) Close() {
	ca.server.Close()
}

// Errors returns all client errors.
func (ca *CAServer) Errors() []error {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return ca.errors
}

// Resolve adds a domain to address resolution for the ca to dial to
// when validating challenges for the domain authorization.
func (ca *CAServer) Resolve(domain, addr string) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.domainAddr[domain] = addr
}

type account struct {
	Resource  string   `json:"resource"`
	Contact   []string `json:"contact,omitempty"`
	Agreement string   `json:"agreement,omitempty"`
}

type discovery struct {
	NewReg   string `json:"new-reg"`
	NewAuthz string `json:"new-authz"`
	NewCert  string `json:"new-cert"`
}

type challenge struct {
	URI   string `json:"uri"`
	Type  string `json:"type"`
	Token string `json:"token"`
}

type authorization struct {
	Status     string      `json:"status"`
	Challenges []challenge `json:"challenges"`

	id     int
	domain string
}

func (ca *CAServer) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", "nonce")
	if r.Method == "HEAD" {
		// a nonce request
		return
	}

	// TODO: Verify nonce header for all POST requests.

	switch {
	default:
		err := fmt.Errorf("unrecognized r.URL.Path: %s", r.URL.Path)
		ca.addError(err)
		http.Error(w, err.Error(), http.StatusBadRequest)

	// Discovery request.
	case r.URL.Path == "/":
		resp := &discovery{
			NewReg:   ca.serverURL("/new-reg"),
			NewAuthz: ca.serverURL("/new-authz"),
			NewCert:  ca.serverURL("/new-cert"),
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			panic(fmt.Sprintf("discovery response: %v", err))
		}

	// Client key registration request.
	case r.URL.Path == "/new-reg":
		acct := new(account)
		accountKey, err := decodePayload(acct, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ca.mu.Lock()
		defer ca.mu.Unlock()
		ca.accounts[accountKey] = acct

		// TODO: Check the user account key against a ca.accountKeys?
		w.Header().Set("Location", ca.serverURL("/account/%s", accountKey))
		w.Header().Set("Link", fmt.Sprintf("<%s>; rel=terms-of-service", ca.serverURL("/tos")))
		if err := json.NewEncoder(w).Encode(acct); err != nil {
			panic(fmt.Sprintf("new-reg response: %v", err))
		}

	case strings.HasPrefix(r.URL.Path, "/account/"):
		requestKey := strings.TrimPrefix(r.URL.Path, "/account/")

		acct := new(account)
		accountKey, err := decodePayload(acct, r.Body)
		if err != nil {
			ca.addError(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if requestKey != accountKey {
			err := fmt.Errorf("request for account %s from account %s", requestKey, accountKey)
			ca.addError(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ca.mu.Lock()
		defer ca.mu.Unlock()

		_, ok := ca.accounts[accountKey]
		if !ok {
			ca.addErrorLocked(err)
			http.Error(w, "account not found", http.StatusNotFound)
			return
		}
		ca.accounts[accountKey] = acct

		w.Header().Set("Location", ca.serverURL("/account/%s", accountKey))
		if err := json.NewEncoder(w).Encode(acct); err != nil {
			panic(fmt.Sprintf("account response: %v", err))
		}

	// Domain authorization request.
	case r.URL.Path == "/new-authz":
		var req struct {
			Identifier struct{ Value string }
		}
		accountKey, err := decodePayload(&req, r.Body)
		if err != nil {
			ca.addError(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ca.mu.Lock()
		defer ca.mu.Unlock()
		acct, ok := ca.accounts[accountKey]
		if !ok {
			err := errors.New("no account; register a new one")
			ca.addErrorLocked(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if acct.Agreement != ca.serverURL("/tos") {
			err := errors.New("account has not accepted TOS")
			ca.addErrorLocked(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		authz, ok := ca.authorizations[req.Identifier.Value]
		if !ok {
			authz = &authorization{
				domain: req.Identifier.Value,
				Status: "pending",
			}
			for _, typ := range ca.challengeTypes {
				authz.Challenges = append(authz.Challenges, challenge{
					Type:  typ,
					URI:   ca.serverURL("/challenge/%s/%s", typ, authz.domain),
					Token: challengeToken(authz.domain, typ),
				})
			}
			ca.authorizations[authz.domain] = authz
		}
		w.Header().Set("Location", ca.serverURL("/authz/%s", authz.domain))
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(authz); err != nil {
			panic(fmt.Sprintf("new authz response: %v", err))
		}

	// Accept tls-alpn-01 challenge type requests.
	// TODO: Add http-01 and dns-01 handlers.
	case strings.HasPrefix(r.URL.Path, "/challenge/tls-alpn-01/"):
		domain := strings.TrimPrefix(r.URL.Path, "/challenge/tls-alpn-01/")
		ca.mu.Lock()
		defer ca.mu.Unlock()
		if _, ok := ca.authorizations[domain]; !ok {
			err := fmt.Errorf("challenge accept: no authz for %q", domain)
			ca.addErrorLocked(err)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		go func(domain string) {
			err := ca.verifyALPNChallenge(domain)
			ca.mu.Lock()
			defer ca.mu.Unlock()
			authz := ca.authorizations[domain]
			if err != nil {
				authz.Status = "invalid"
				return
			}
			authz.Status = "valid"

		}(domain)
		w.Write([]byte("{}"))

	// Get authorization status requests.
	case strings.HasPrefix(r.URL.Path, "/authz/"):
		domain := strings.TrimPrefix(r.URL.Path, "/authz/")
		ca.mu.Lock()
		defer ca.mu.Unlock()
		authz, ok := ca.authorizations[domain]
		if !ok {
			http.Error(w, fmt.Sprintf("no authz for %q", domain), http.StatusNotFound)
			return
		}
		if err := json.NewEncoder(w).Encode(authz); err != nil {
			panic(fmt.Sprintf("get authz for %q response: %v", domain, err))
		}

	// Cert issuance request.
	case r.URL.Path == "/new-cert":
		var req struct {
			CSR string `json:"csr"`
		}
		_, err := decodePayload(&req, r.Body)
		if err != nil {
			ca.addError(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		b, _ := base64.RawURLEncoding.DecodeString(req.CSR)
		csr, err := x509.ParseCertificateRequest(b)
		if err != nil {
			ca.addError(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		names := unique(append(csr.DNSNames, csr.Subject.CommonName))
		if err := ca.matchWhitelist(names); err != nil {
			ca.addError(err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if err := ca.authorized(names); err != nil {
			ca.addError(err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		der, err := ca.leafCert(csr)
		if err != nil {
			err = fmt.Errorf("new-cert response: ca.leafCert: %v", err)
			ca.addError(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		w.Header().Set("Link", fmt.Sprintf("<%s>; rel=up", ca.serverURL("/ca-cert")))
		w.WriteHeader(http.StatusCreated)
		w.Write(der)

	// CA chain cert request.
	case r.URL.Path == "/ca-cert":
		w.Write(ca.rootCert)
	}
}

func (ca *CAServer) addError(err error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.addErrorLocked(err)
}

func (ca *CAServer) addErrorLocked(err error) {
	ca.errors = append(ca.errors, err)
}

func (ca *CAServer) serverURL(format string, arg ...interface{}) string {
	return ca.server.URL + fmt.Sprintf(format, arg...)
}

func (ca *CAServer) matchWhitelist(dnsNames []string) error {
	if len(ca.domainsWhitelist) == 0 {
		return nil
	}
	var nomatch []string
	for _, name := range dnsNames {
		i := sort.SearchStrings(ca.domainsWhitelist, name)
		if i == len(ca.domainsWhitelist) || ca.domainsWhitelist[i] != name {
			nomatch = append(nomatch, name)
		}
	}
	if len(nomatch) > 0 {
		return fmt.Errorf("matchWhitelist: some domains don't match: %q", nomatch)
	}
	return nil
}

func (ca *CAServer) authorized(dnsNames []string) error {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	var noauthz []string
	for _, name := range dnsNames {
		authz, ok := ca.authorizations[name]
		if !ok || authz.Status != "valid" {
			noauthz = append(noauthz, name)
		}
	}
	if len(noauthz) > 0 {
		return fmt.Errorf("CAServer: no authz for %q", noauthz)
	}
	return nil
}

func (ca *CAServer) leafCert(csr *x509.CertificateRequest) (der []byte, err error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.certCount++ // next leaf cert serial number
	leaf := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(ca.certCount)),
		Subject:               pkix.Name{Organization: []string{"Test Acme Co"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              csr.DNSNames,
		BasicConstraintsValid: true,
	}
	if len(csr.DNSNames) == 0 {
		leaf.DNSNames = []string{csr.Subject.CommonName}
	}
	return x509.CreateCertificate(rand.Reader, leaf, ca.rootTemplate, csr.PublicKey, ca.rootKey)
}

func (ca *CAServer) addr(domain string) (string, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	addr, ok := ca.domainAddr[domain]
	if !ok {
		return "", fmt.Errorf("CAServer: no addr resolution for %q", domain)
	}
	return addr, nil
}

func (ca *CAServer) verifyALPNChallenge(domain string) error {
	const acmeALPNProto = "acme-tls/1"

	addr, err := ca.addr(domain)
	if err != nil {
		return err
	}
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
		NextProtos:         []string{acmeALPNProto},
	})
	if err != nil {
		return err
	}
	if v := conn.ConnectionState().NegotiatedProtocol; v != acmeALPNProto {
		return fmt.Errorf("CAServer: verifyALPNChallenge: negotiated proto is %q; want %q", v, acmeALPNProto)
	}
	if n := len(conn.ConnectionState().PeerCertificates); n != 1 {
		return fmt.Errorf("len(PeerCertificates) = %d; want 1", n)
	}
	// TODO: verify conn.ConnectionState().PeerCertificates[0]
	return nil
}

func decodePayload(v interface{}, r io.Reader) (string, error) {
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(r); err != nil {
		return "", errors.New("unable to read JOSE body")
	}
	jws, err := jose.ParseSigned(buf.String())
	if err != nil {
		return "", errors.New("malformed JOSE body")
	}
	if len(jws.Signatures) == 0 {
		return "", errors.New("invalid JOSE body; no signatures")
	}
	sig := jws.Signatures[0]
	key := sig.Protected.JSONWebKey
	if key == nil {
		return "", errors.New("invalid JOSE body; missing key in header")
	}

	//payload := jws.UnsafePayloadWithoutVerification()
	payload, err := jws.Verify(key.Key)
	if err != nil {
		return "", fmt.Errorf("invalid signature: %v", err)
	}
	if err := json.Unmarshal(payload, v); err != nil {
		return "", errors.New("malformed payload")
	}

	keyDER, err := x509.MarshalPKIXPublicKey(key.Key)
	if err != nil {
		return "", errors.New("unable to marshal key")
	}
	keyHash := sha256.Sum256(keyDER)
	return base64.RawURLEncoding.EncodeToString(keyHash[:]), nil
}

func challengeToken(domain, challType string) string {
	return fmt.Sprintf("token-%s-%s", domain, challType)
}

func unique(a []string) []string {
	seen := make(map[string]bool)
	var res []string
	for _, s := range a {
		if s != "" && !seen[s] {
			seen[s] = true
			res = append(res, s)
		}
	}
	return res
}
