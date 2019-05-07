package sshpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"text/template"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

var randReader = rand.New(rand.NewSource(1234))

type testParams struct {
	Signer      ssh.Signer
	Certificate *ssh.Certificate
	CertChecker *ssh.CertChecker
	Fingerprint string
}

func principal(name string) func(*ssh.Certificate) {
	return func(cert *ssh.Certificate) {
		cert.ValidPrincipals = append(cert.ValidPrincipals, name)
	}
}

func newTest(t *testing.T, opts ...func(*ssh.Certificate)) *testParams {
	privkey, err := ecdsa.GenerateKey(elliptic.P256(), randReader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromSigner(privkey)
	require.NoError(t, err)
	certificate := &ssh.Certificate{
		Key:         signer.PublicKey(),
		CertType:    ssh.HostCert,
		ValidAfter:  0,
		ValidBefore: ssh.CertTimeInfinity,
	}
	for _, opt := range opts {
		opt(certificate)
	}
	err = certificate.SignCert(randReader, signer)
	require.NoError(t, err)
	certChecker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			return reflect.DeepEqual(auth, signer.PublicKey())
		},
	}
	return &testParams{
		Signer:      signer,
		Certificate: certificate,
		CertChecker: certChecker,
		Fingerprint: ssh.FingerprintSHA256(certificate),
	}
}

func TestHandshake(t *testing.T) {
	tt := newTest(t, principal("ec2abcdef-uswest1"))

	c := &Client{
		cert:        tt.Certificate,
		signer:      tt.Signer,
		trustDomain: "foo.local",
	}
	s := &Server{
		certChecker:       tt.CertChecker,
		agentPathTemplate: DefaultAgentPathTemplate,
		trustDomain:       "foo.local",
	}

	client := c.NewHandshake()
	server := s.NewHandshake()

	attestation, err := client.AttestationData()
	require.NoError(t, err)

	err = server.VerifyAttestationData(attestation)
	require.NoError(t, err)

	challengeReq, err := server.IssueChallenge()
	require.NoError(t, err)

	challengeRes, err := client.RespondToChallenge(challengeReq)
	require.NoError(t, err)

	err = server.VerifyChallengeResponse(challengeRes)
	require.NoError(t, err)

	spiffeid, err := server.AgentID()
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("spiffe://foo.local/spire/agent/sshpop/%s", tt.Fingerprint), spiffeid)
}

func TestServerSpiffeID(t *testing.T) {
	tt := newTest(t, principal("ec2abcdef-uswest1"))
	agentPathTemplate, err := template.New("agent-path").Parse("static/{{ index .ValidPrincipals 0 }}")
	require.NoError(t, err)

	s := &ServerHandshake{
		s: &Server{
			trustDomain:       "foo.local",
			agentPathTemplate: agentPathTemplate,
		},
		cert: tt.Certificate,
	}
	spiffeid, err := s.AgentID()
	require.NoError(t, err)
	require.Equal(t, "spiffe://foo.local/spire/agent/static/ec2abcdef-uswest1", spiffeid)
}

func newTestHandshake(t *testing.T) (*ClientHandshake, *ServerHandshake) {
	tt := newTest(t, principal("ec2abcdef-uswest1.test.internal"))
	trustDomain := "foo.local"
	c := &Client{
		signer:      tt.Signer,
		cert:        tt.Certificate,
		trustDomain: trustDomain,
	}
	s := &Server{
		trustDomain:       trustDomain,
		agentPathTemplate: DefaultAgentPathTemplate,
		certChecker:       tt.CertChecker,
	}
	return c.NewHandshake(), s.NewHandshake()
}

func TestAttestationDataVerifies(t *testing.T) {
	c, s := newTestHandshake(t)
	attestationData, err := c.AttestationData()
	require.NoError(t, err)
	require.NoError(t, s.VerifyAttestationData(attestationData))
}

func TestVerifyAttestationData(t *testing.T) {
	c, s := newTestHandshake(t)

	tests := []struct {
		desc                  string
		attestationData       []byte
		serverCanonicalDomain string
		expectErr             string
		expectHostname        string
	}{
		{
			desc:            "bad format",
			attestationData: []byte("{{"),
			expectErr:       "sshpop: failed to unmarshal data",
		},
		{
			desc:            "no certs",
			attestationData: []byte("{}"),
			expectErr:       "sshpop: no certificate in response",
		},
		{
			desc:            "bad cert format",
			attestationData: []byte("{\"certificate\": \"aGVsbG8K\"}"),
			expectErr:       "sshpop: failed to parse public key",
		},
		{
			desc: "cert is pubkey",
			attestationData: func() []byte {
				tt := newTest(t)
				return marshalAttestationData(t, tt.Certificate.Key.Marshal())
			}(),
			expectErr: "sshpop: pubkey in response is not a certificate",
		},
		{
			desc: "cert has no valid principals",
			attestationData: func() []byte {
				tt := newTest(t)
				return marshalAttestationData(t, tt.Certificate.Marshal())
			}(),
			expectErr: "sshpop: cert has no valid principals",
		},
		{
			desc: "cert isn't signed by a known authority",
			attestationData: func() []byte {
				tt := newTest(t, principal("foo"))
				return marshalAttestationData(t, tt.Certificate.Marshal())
			}(),
			expectErr: "sshpop: failed to check host key",
		},
		{
			desc:            "cert is signed by a known authority",
			attestationData: marshalAttestationData(t, c.c.cert.Marshal()),
			expectHostname:  "ec2abcdef-uswest1.test.internal",
		},
		{
			desc:                  "cert is signed by a known authority with canonicalized domain",
			attestationData:       marshalAttestationData(t, c.c.cert.Marshal()),
			serverCanonicalDomain: "test.internal",
			expectHostname:        "ec2abcdef-uswest1",
		},
		{
			desc:                  "cert is signed by a known authority with bad canonicalized domain",
			attestationData:       marshalAttestationData(t, c.c.cert.Marshal()),
			serverCanonicalDomain: "foo.internal",
			expectErr:             `sshpop: failed to decanonicalize hostname: cert principal is not in domain ".foo.internal"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			s.state = stateServerInit
			s.s.canonicalDomain = tt.serverCanonicalDomain

			err := s.VerifyAttestationData(tt.attestationData)
			if tt.expectErr == "" {
				require.NoError(t, err)
				if tt.expectHostname != "" {
					require.Equal(t, tt.expectHostname, s.hostname)
				}
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectErr)
		})
	}
}

func marshalAttestationData(t *testing.T, cert []byte) []byte {
	b, err := json.Marshal(attestationData{
		Certificate: cert,
	})
	require.NoError(t, err)
	return b
}

func TestIssueChallengeUniqueness(t *testing.T) {
	_, s := newTestHandshake(t)
	challenges := make(map[string]struct{})
	for i := 0; i < 10000; i++ {
		s.state = stateAttestationDataVerified
		challenge, err := s.IssueChallenge()
		require.NoError(t, err)
		_, exists := challenges[string(challenge)]
		require.False(t, exists, "challenge should not already exist")
		challenges[string(challenge)] = struct{}{}
	}
}

func TestRespondToChallenge(t *testing.T) {
	c, s := newTestHandshake(t)

	tests := []struct {
		desc         string
		challengeReq []byte
		expectErr    string
	}{
		{
			desc:         "bad format",
			challengeReq: []byte("{{"),
			expectErr:    "sshpop: failed to unmarshal challenge request",
		},
		{
			desc:         "nonce size mismatch",
			challengeReq: []byte("{\"nonce\": \"c2hvcnQK\"}"),
			expectErr:    "sshpop: failed to combine nonces: invalid challenge nonce size",
		},
		{
			desc: "success",
			challengeReq: func() []byte {
				s.state = stateAttestationDataVerified
				req, err := s.IssueChallenge()
				require.NoError(t, err)
				return req
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			c.state = stateProvidedAttestationData
			_, err := c.RespondToChallenge(tt.challengeReq)
			if tt.expectErr == "" {
				require.NoError(t, err)
				require.Equal(t, stateRespondedToChallenge, c.state)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectErr)
			require.Equal(t, stateProvidedAttestationData, c.state)
		})
	}
}

func TestVerifyChallengeResponse(t *testing.T) {
	c, s := newTestHandshake(t)

	tests := []struct {
		desc         string
		challengeRes func([]byte) []byte
		expectErr    string
	}{
		{
			desc: "bad format",
			challengeRes: func([]byte) []byte {
				return []byte("{{")
			},
			expectErr: "sshpop: failed to unmarshal challenge response",
		},
		{
			desc: "nonce size mismatch",
			challengeRes: func([]byte) []byte {
				return []byte("{\"nonce\": \"c2hvcnQK\"}")
			},
			expectErr: "sshpop: failed to combine nonces: invalid response nonce size",
		},
		{
			desc: "cert isn't signed by a known authority",
			challengeRes: func(req []byte) []byte {
				c, _ := newTestHandshake(t)
				c.state = stateProvidedAttestationData
				res, err := c.RespondToChallenge(req)
				require.NoError(t, err)
				return res
			},
			expectErr: "sshpop: failed to verify signature",
		},
		{
			desc: "success",
			challengeRes: func(req []byte) []byte {
				c.state = stateProvidedAttestationData
				res, err := c.RespondToChallenge(req)
				require.NoError(t, err)
				return res
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			s.state = stateAttestationDataVerified
			s.cert = c.c.cert
			req, err := s.IssueChallenge()
			require.NoError(t, err)

			res := tt.challengeRes(req)
			err = s.VerifyChallengeResponse(res)
			if tt.expectErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectErr)
		})
	}
}

func TestDecanonicalizeHostname(t *testing.T) {
	tests := []struct {
		desc           string
		fqdn           string
		domain         string
		expectHostname string
		expectErr      string
	}{
		{
			desc:           "success 1",
			fqdn:           "foo.bar.internal",
			domain:         "bar.internal",
			expectHostname: "foo",
		},
		{
			desc:      "bad wrong canonical domain",
			fqdn:      "foo.bar.baz.internal",
			domain:    "bar.internal",
			expectErr: `cert principal is not in domain ".bar.internal"`,
		},
		{
			desc:      "bad wrong canonical domain 2",
			fqdn:      "foo.internal",
			domain:    "foo.internal",
			expectErr: `cert principal is not in domain ".foo.internal"`,
		},
		{
			desc:           "no configured domain",
			fqdn:           "foo.bar.internal",
			domain:         "",
			expectHostname: "foo.bar.internal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			hostname, err := decanonicalizeHostname(tt.fqdn, tt.domain)
			if tt.expectErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectHostname, hostname)
		})
	}
}
