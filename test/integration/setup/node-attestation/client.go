package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"log"
	"time"
	mathrand "math/rand"
	"github.com/spiffe/spire/proto/spire-next/api/server/agent/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/test/integration/setup/itclient"
	"github.com/spiffe/spire/test/testkey"
)

var (
	key = testkey.MustEC256()
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := itclient.NewLocalServerClient(ctx)
	defer c.Release()

	// Validate call to New Downstream X509 CA
	err := testAgentApi(ctx, c)
	if err != nil {
		log.Fatal(fmt.Sprintf("%v", err))
	}
}

func testAgentApi(ctx context.Context, c *itclient.LocalServerClient) error {
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return fmt.Errorf("fails to create CSR: %v", err)
	}

	s1 := mathrand.NewSource(time.Now().UnixNano())
	tokenId := mathrand.New(s1).Intn(1000000)

	tokenName := fmt.Sprintf("test_token_%v", tokenId)

	// Create a join token using the local socket connection (simulating the CLI running on the spire-server)
	agentClient := c.AgentClient()
	_, err = agentClient.CreateJoinToken(ctx, &agent.CreateJoinTokenRequest{Ttl: 1000, Token: tokenName})
	if err != nil {
		return fmt.Errorf("unable to create join token: %v", err)
	}

	// Now do agent attestation using that same join token. This will give us an SVID
	stream, err := agentClient.AttestAgent(ctx)
	if err != nil {
		return fmt.Errorf("failed to open stream to attest agent: %v", err)
	}

	stream.Send(&agent.AttestAgentRequest{ 
		Step: &agent.AttestAgentRequest_Params_{
			Params: &agent.AttestAgentRequest_Params{
				Data: &types.AttestationData{Type: "join_token", Payload: tokenName},
				Params: &agent.AgentX509SVIDParams{Csr: csr},
			},
		},
	})
	response, err := stream.Recv()
	result := response.Step.(*agent.AttestAgentResponse_Result_).Result
	svid := result.Svid.CertChain[0]
	cert, err := x509.ParseCertificate(svid)
	if err != nil {
		return fmt.Errorf("failed to parse cert: %v", err)
	}

	// Re-connect over TCP, simulating a working spire-agent connection. Use the cert obtained through 
	// attestation as the client cert (and don't bother validating the server cert)
	agentRemoteConn := itclient.NewWithCert(ctx, *cert, key)
	agentRemoteClient := agentRemoteConn.AgentClient()

	// Now renew the agent cert
	_, err = agentRemoteClient.RenewAgent(ctx, &agent.RenewAgentRequest{ 
				Params: &agent.AgentX509SVIDParams{Csr: csr},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to renew agent: %v", err)
	}


	// Now ban the agent using the local connection
	_, err = agentClient.BanAgent(ctx, &agent.BanAgentRequest{
		Id: result.Svid.Id})
	if err != nil {
		return fmt.Errorf("failed to ban agent: %v", err)
	}
        _, err = agentRemoteClient.RenewAgent(ctx, &agent.RenewAgentRequest{ 
				Params: &agent.AgentX509SVIDParams{Csr: csr},
		},
	)
	if err == nil {
		return fmt.Errorf("Banning agent had no effect")
	}

	return nil
}
