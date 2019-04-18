package sshpop

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"text/template"

	"github.com/spiffe/spire/pkg/common/idutil"
	"golang.org/x/crypto/ssh"
)

type serverHandshakeState int
type clientHandshakeState int

const (
	stateServerInit serverHandshakeState = iota
	stateAttestationDataVerified
	stateChallengeIssued
	stateChallengeVerified
)

const (
	stateClientInit clientHandshakeState = iota
	stateProvidedAttestationData
	stateRespondedToChallenge
)

// ClientHandshake is a single-use object for an agent to do node attestation.
//
// The handshake comprises a state machine that is not goroutine safe.
type ClientHandshake struct {
	c     *Client
	state clientHandshakeState
}

// ServerHandshake is a single-use object for a server to do node attestation.
//
// The handshake comprises a state machine that is not goroutine safe.
type ServerHandshake struct {
	s     *Server
	cert  *ssh.Certificate
	nonce []byte
	state serverHandshakeState
}

type attestationData struct {
	Certificate []byte
}

type challengeRequest struct {
	Nonce []byte
}

type challengeResponse struct {
	Nonce     []byte
	Signature *ssh.Signature
}

func (c *ClientHandshake) SpiffeID() (string, error) {
	return makeSpiffeID(c.c.trustDomain, c.c.agentPathTemplate, c.c.cert)
}

func (c *ClientHandshake) AttestationData() ([]byte, error) {
	if c.state != stateClientInit {
		return nil, Errorf("client must be in init state to provide attestation data")
	}
	data, err := json.Marshal(attestationData{
		Certificate: c.c.cert.Marshal(),
	})
	if err != nil {
		return nil, Errorf("failed to marshal attestation data: %v", err)
	}
	c.state = stateProvidedAttestationData
	return data, nil
}

func (c *ClientHandshake) RespondToChallenge(req []byte) ([]byte, error) {
	if c.state != stateProvidedAttestationData {
		return nil, Errorf("client must provide attestation data to respond to challenge")
	}
	challenge := new(challengeRequest)
	if err := json.Unmarshal(req, challenge); err != nil {
		return nil, Errorf("failed to unmarshal challenge request: %v", err)
	}
	nonce, err := newNonce()
	if err != nil {
		return nil, Errorf("failed to generate nonce: %v", err)
	}
	toBeSigned, err := combineNonces(challenge.Nonce, nonce)
	if err != nil {
		return nil, Errorf("failed to combine nonces: %v", err)
	}
	sig, err := c.c.signer.Sign(rand.Reader, toBeSigned)
	if err != nil {
		return nil, Errorf("failed to sign data: %v", err)
	}
	b, err := json.Marshal(challengeResponse{
		Nonce:     nonce,
		Signature: sig,
	})
	if err != nil {
		return nil, Errorf("failed to marshal response: %v", err)
	}
	c.state = stateRespondedToChallenge
	return b, nil
}

func (s *ServerHandshake) VerifyAttestationData(data []byte) error {
	if s.state != stateServerInit {
		return Errorf("server must be in init state to verify data")
	}
	attestation := new(attestationData)
	if err := json.Unmarshal(data, attestation); err != nil {
		return Errorf("failed to unmarshal data: %v", err)
	}
	if len(attestation.Certificate) == 0 {
		return Errorf("no certificate in response")
	}
	pubkey, err := ssh.ParsePublicKey(attestation.Certificate)
	if err != nil {
		return Errorf("failed to parse public key: %v", err)
	}
	cert, ok := pubkey.(*ssh.Certificate)
	if !ok {
		return Errorf("pubkey in response is not a certificate")
	}
	if len(cert.ValidPrincipals) == 0 {
		return Errorf("cert has no valid principals")
	}
	addr := fmt.Sprintf("%s:22", cert.ValidPrincipals[0])
	if err := s.s.certChecker.CheckHostKey(addr, &net.IPAddr{}, cert); err != nil {
		return Errorf("failed to check host key: %v", err)
	}
	s.cert = cert
	s.state = stateAttestationDataVerified
	return nil
}

func (s *ServerHandshake) IssueChallenge() ([]byte, error) {
	if s.state != stateAttestationDataVerified {
		return nil, Errorf("server must verify attestation data to issue a challenge")
	}
	nonce, err := newNonce()
	if err != nil {
		return nil, Errorf("failed to generate nonce: %v", err)
	}
	s.nonce = nonce
	challenge := challengeRequest{
		Nonce: nonce,
	}
	b, err := json.Marshal(challenge)
	if err != nil {
		return nil, Errorf("failed to marshal challenge request: %v", err)
	}
	s.state = stateChallengeIssued
	return b, nil
}

func (s *ServerHandshake) VerifyChallengeResponse(res []byte) error {
	if s.state != stateChallengeIssued {
		return Errorf("server must issue a challenge to verify a challenge response")
	}
	challenge := new(challengeResponse)
	if err := json.Unmarshal(res, challenge); err != nil {
		return Errorf("failed to unmarshal challenge response: %v", err)
	}
	toBeSigned, err := combineNonces(s.nonce, challenge.Nonce)
	if err != nil {
		return Errorf("failed to combine nonces: %v", err)
	}
	if err := s.cert.Verify(toBeSigned, challenge.Signature); err != nil {
		return Errorf("failed to verify signature: %v", err)
	}
	s.state = stateChallengeVerified
	return nil
}

func (s *ServerHandshake) SpiffeID() (string, error) {
	return makeSpiffeID(s.s.trustDomain, s.s.agentPathTemplate, s.cert)
}

func newNonce() ([]byte, error) {
	b := make([]byte, nonceLen)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func combineNonces(challenge, response []byte) ([]byte, error) {
	if len(challenge) != nonceLen {
		return nil, errors.New("invalid challenge nonce size")
	}
	if len(response) != nonceLen {
		return nil, errors.New("invalid response nonce size")
	}
	h := sha256.New()
	h.Write(challenge)
	h.Write(response)
	return h.Sum(nil), nil
}

func makeSpiffeID(trustDomain string, agentPathTemplate *template.Template, cert *ssh.Certificate) (string, error) {
	var agentPath bytes.Buffer
	if err := agentPathTemplate.Execute(&agentPath, agentPathTemplateData{
		Certificate: cert,
		PluginName:  PluginName,
		Fingerprint: ssh.FingerprintSHA256(cert),
	}); err != nil {
		return "", err
	}
	return idutil.AgentURI(trustDomain, agentPath.String()).String(), nil
}
