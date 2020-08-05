package main

import (
	"context"
	"crypto/rand"
	x509 "crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	mathrand "math/rand"
	"time"

	agent "github.com/spiffe/spire/proto/spire/api/server/agent/v1"
	types "github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/integration/setup/itclient"
	"github.com/spiffe/spire/test/testkey"
)

var (
	key         = testkey.MustEC256()
	testStep    = flag.String("testStep", "", "jointoken, attest, ban, renew")
	tokenName   = flag.String("tokenName", "tokenName", "token for attestation")
	certificate = flag.String("certificate", "", "certificate for api connection")
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	flag.Parse()
	switch *testStep {
	case "jointoken":
		doJoinTokenStep(ctx)
	case "jointokenattest":
		doJoinTokenAttestStep(ctx, *tokenName)
	case "ban":
		doBanStep(ctx)
	case "renew":
		doRenewStep(ctx)
	default:
		log.Fatalf("error: unknown test step\n")
	}
}

func doJoinTokenStep(ctx context.Context) {
	c := itclient.NewLocalServerClient(ctx)
	defer c.Release()

	s1 := mathrand.NewSource(time.Now().UnixNano())
	tokenID := mathrand.New(s1).Intn(1000000)
	tokenName := fmt.Sprintf("test_token_%v", tokenID)

	// Create a join token using the local socket connection (simulating the CLI running on the spire-server)
	agentClient := c.AgentClient()
	_, err := agentClient.CreateJoinToken(ctx, &agent.CreateJoinTokenRequest{Ttl: 1000, Token: tokenName})
	if err != nil {
		log.Fatalf("unable to create join token: %v", err)
	}
	// Print the join token so it can be easily used in the subsequent test
	fmt.Printf("%v\n", tokenName)
}

func doJoinTokenAttestStep(ctx context.Context, tokenName string) {
	// Now do agent attestation using the join token and save the resulting SVID to a file. This will give us an SVID
	agentRemoteConn := itclient.NewInsecure(ctx)
	defer agentRemoteConn.Release()
	agentRemoteClient := agentRemoteConn.AgentClient()

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		log.Fatalf("failed to create CSR: %v\n", err)
	}

	stream, err := agentRemoteClient.AttestAgent(ctx)
	if err != nil {
		log.Fatalf("failed to open stream to attest agent: %v\n", err)
	}

	err = stream.Send(&agent.AttestAgentRequest{
		Step: &agent.AttestAgentRequest_Params_{
			Params: &agent.AttestAgentRequest_Params{
				Data:   &types.AttestationData{Type: "join_token", Payload: tokenName},
				Params: &agent.AgentX509SVIDParams{Csr: csr},
			},
		},
	})
	if err != nil {
		log.Fatalf("failed to send to stream to attest agent: %v\n", err)
	}

	response, err := stream.Recv()
	if err != nil {
		log.Fatalf("failed receive response to AttestAgent: %v\n", err)
	}

	result := response.Step.(*agent.AttestAgentResponse_Result_).Result
	svid := result.Svid.CertChain[0]
	_, err = x509.ParseCertificate(svid)
	if err != nil {
		log.Fatalf("failed to parse cert: %v\n", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: svid})

	// Print the SVID so it can easily be used in the next step
	fmt.Printf("%s\n\n", certPEM)
}

func doRenewStep(ctx context.Context) {
	block, _ := pem.Decode([]byte(*certificate))
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatalf("failed to decode PEM block containing public key, %v\n", *certificate)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse cert: %v\n", err)
	}

	agentRemoteConn := itclient.NewWithCert(ctx, cert, key)
	defer agentRemoteConn.Release()
	agentRemoteClient := agentRemoteConn.AgentClient()

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		log.Fatalf("failed to create CSR: %v", err)
	}

	// Now renew the agent cert
	response, err := agentRemoteClient.RenewAgent(ctx, &agent.RenewAgentRequest{
		Params: &agent.AgentX509SVIDParams{Csr: csr},
	})
	if err != nil {
		log.Fatalf("failed to RenewAgent: %v", err)
	}
	svid := response.Svid.CertChain[0]
	_, err = x509.ParseCertificate(svid)
	if err != nil {
		log.Fatalf("failed to parse cert: %v\n", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: svid})
	if string(certPEM) == *certificate {
		log.Fatalf("renewed agent successfully, but the old cert and the new cert are identical\n")
	}
	// Print the certificate so it can easily be used in the next step
	fmt.Printf("%s\n\n", certPEM)
}

func doBanStep(ctx context.Context) {
	c := itclient.NewLocalServerClient(ctx)
	defer c.Release()

	agentClient := c.AgentClient()
	// Now ban the agent using the local connection
	_, err := agentClient.BanAgent(ctx, &agent.BanAgentRequest{Id: &types.SPIFFEID{TrustDomain: "domain.test", Path: "spire/agent/join_token/" + *tokenName}})
	if err != nil {
		log.Fatalf("failed to ban agent: %v", err)
	}
	// This doesn't return anything
}
