package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	x509 "crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"time"

	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	agent "github.com/spiffe/spire/proto/spire/api/server/agent/v1"
	types "github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/integration/setup/itclient"
	"github.com/spiffe/spire/test/testkey"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

var (
	key         = testkey.MustEC256()
	testStep    = flag.String("testStep", "", "jointoken, attest, ban, renew")
	tokenName   = flag.String("tokenName", "tokenName", "token for attestation")
	certificate = flag.String("certificate", "", "certificate for api connection")
	popCert     = flag.String("popCertficate", "/opt/spire/conf/agent/test.crt.pem", "certificate for x509pop attestation")
	popKey      = flag.String("popKey", "/opt/spire/conf/agent/test.key.pem", "key for x509pop attestation")
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
	case "x509pop":
		doX509popStep(ctx)
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
				Data:   &types.AttestationData{Type: "join_token", Payload: []byte(tokenName)},
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

// doX509popStep tests attestation using x509pop
// Steps:
// - Attest agent
// - Renew agent
// - Delete agent
// - Reattest deleted agent
// - Ban agent
// - Reattest banned agent (must fail because it is banned)
// - Delete agent
// - Reattest deleted agent (must succeed after removing)
func doX509popStep(ctx context.Context) {
	c := itclient.New(ctx)
	// Create an admin client to ban/delete agent
	defer c.Release()
	client := c.AgentClient()

	// Attest agent
	svidResp, err := x509popAttest(ctx)
	if err != nil {
		log.Fatalf("Failed to attest: %v", err)
	}

	// Renew agent
	if err := x509popRenew(ctx, svidResp); err != nil {
		log.Fatalf("failed to renew agent: %v", err)
	}

	// Delete agent
	if err := deleteAgent(ctx, client, svidResp.Id); err != nil {
		log.Fatalf("Failed to delete agent: %v", err)
	}

	// Reattest deleted agent
	svidResp, err = x509popAttest(ctx)
	if err != nil {
		log.Fatalf("Failed to attest deleted agent: %v", err)
	}

	// Ban agent
	if err := banAgent(ctx, client, svidResp.Id); err != nil {
		log.Fatalf("Failed to ban agent")
	}

	// Reattest banned agent, it MUST fail
	_, err = x509popAttest(ctx)
	switch status.Code(err) {
	case codes.OK:
		log.Fatal("Error expected when attesting banned agent")
	case codes.PermissionDenied:
		if status.Convert(err).Message() != "failed to attest: agent is banned" {
			log.Fatalf("Unexpected error returned: %v", err)
		}
	default:
		log.Fatalf("Unexpected error returned: %v", err)
	}

	// Delete banned agent
	if err := deleteAgent(ctx, client, svidResp.Id); err != nil {
		log.Fatalf("Failed to delete agent: %v", err)
	}

	// Reattest deleted agent, now MUST be successful
	_, err = x509popAttest(ctx)
	if err != nil {
		log.Fatalf("Failed to attest deleted agent: %v", err)
	}
}

// x509popAttest attests agent using x509pop
func x509popAttest(ctx context.Context) (*types.X509SVID, error) {
	log.Println("Attesting agent...")

	// Create insecure connection
	conn := itclient.NewInsecure(ctx)
	defer conn.Release()
	client := conn.AgentClient()

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %v", err)
	}

	pair, err := tls.LoadX509KeyPair(*popCert, *popKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load key pair: %v", err)
	}

	data := &x509pop.AttestationData{
		Certificates: pair.Certificate,
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	stream, err := client.AttestAgent(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create stream: %v", err)
	}
	if err := stream.Send(&agent.AttestAgentRequest{
		Step: &agent.AttestAgentRequest_Params_{
			Params: &agent.AttestAgentRequest_Params{
				Data: &types.AttestationData{
					Type:    "x509pop",
					Payload: payload,
				},
				Params: &agent.AgentX509SVIDParams{
					Csr: csr,
				},
			},
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to send attestation request: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("failed to call stream: %v", err)
	}

	challenge := new(x509pop.Challenge)
	if err := json.Unmarshal(resp.GetChallenge(), challenge); err != nil {
		return nil, fmt.Errorf("failed to unmarshal challenge: %v", err)
	}

	response, err := x509pop.CalculateResponse(pair.PrivateKey, challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate challenge response: %v", err)
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal challenge response: %v", err)
	}

	if err := stream.Send(&agent.AttestAgentRequest{
		Step: &agent.AttestAgentRequest_ChallengeResponse{
			ChallengeResponse: responseBytes,
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to send challenge: %v", err)
	}

	resp, err = stream.Recv()
	if err != nil {
		return nil, err
	}

	if _, err := stream.Recv(); err != io.EOF {
		return nil, fmt.Errorf("expect stream to close after challenge complete: %v", err)
	}

	return resp.GetResult().Svid, nil
}

// x509popRenew creates a connection using provided svid and renew it
func x509popRenew(ctx context.Context, x509Svid *types.X509SVID) error {
	log.Println("Renewing agent...")

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %v", err)
	}

	cert, err := x509.ParseCertificate(x509Svid.CertChain[0])
	if err != nil {
		return fmt.Errorf("failed to parse cert: %v", err)
	}

	conn := itclient.NewWithCert(ctx, cert, key)
	defer conn.Release()
	client := conn.AgentClient()

	resp, err := client.RenewAgent(ctx, &agent.RenewAgentRequest{
		Params: &agent.AgentX509SVIDParams{
			Csr: csr,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to renew agent: %v", err)
	}

	if !proto.Equal(resp.Svid.Id, x509Svid.Id) {
		return fmt.Errorf("uxexpected ID: %q, expected: %q", resp.Svid.Id.String(), x509Svid.Id.String())
	}

	return nil
}

// deleteAgent delete agent using "admin" connection
func deleteAgent(ctx context.Context, client agent.AgentClient, id *types.SPIFFEID) error {
	log.Println("Deleting agent...")
	_, err := client.DeleteAgent(ctx, &agent.DeleteAgentRequest{
		Id: id,
	})
	return err
}

// banAgent ban agent using "admin" connection
func banAgent(ctx context.Context, client agent.AgentClient, id *types.SPIFFEID) error {
	log.Println("Banning agent...")
	_, err := client.BanAgent(ctx, &agent.BanAgentRequest{
		Id: id,
	})
	return err
}
