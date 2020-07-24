package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	//"encoding/base64"
	"errors"
	"fmt"
	"log"
	"time"
	mathrand "math/rand"
	//"github.com/golang/protobuf/proto"
	//"github.com/spiffe/spire/proto/spire-next/api/server/bundle/v1"
	"github.com/spiffe/spire/proto/spire-next/api/server/agent/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/test/integration/setup/itclient"
	"github.com/spiffe/spire/test/testkey"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	key = testkey.MustEC256()
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := itclient.NewLocalServerClient(ctx)
	defer c.Release()

	failures := make(map[string]error)

	// Validate call to New Downstream X509 CA
	if err := validateAttestAgent(ctx, c); err != nil {
		failures["AttestAgent"] = err
	}

	if len(failures) == 0 {
		// Success
		return
	}

	msg := ""
	for rpcName, err := range failures {
		msg += fmt.Sprintf("RPC %q: %v\n", rpcName, err)
	}
	log.Fatal(msg)
}

func validateAttestAgent(ctx context.Context, c *itclient.LocalServerClient) error {
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return fmt.Errorf("fails to create CSR: %v", err)
	}

	s1 := mathrand.NewSource(time.Now().UnixNano())
	tokenId := mathrand.New(s1).Intn(1000000)

	tokenName := fmt.Sprintf("test_token_%v", tokenId)
	
	agentClient := c.AgentClient()
	_, err = agentClient.CreateJoinToken(ctx, &agent.CreateJoinTokenRequest{Ttl: 1000, Token: tokenName})
	if err != nil {
		return fmt.Errorf("unable to create join token: %v", err)
	}

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
	fmt.Printf("svids %v %v\n", err, cert)
	if err != nil {
		return fmt.Errorf("failed to parse cert: %v", err)
	}

	agentConn := itclient.NewWithCert(ctx, *cert, key)
	agentConnClient := agentConn.AgentClient()
	_, err = agentConnClient.RenewAgent(ctx, &agent.RenewAgentRequest{ 
				Params: &agent.AgentX509SVIDParams{Csr: csr},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to renew agent: %v %v", err, tokenName)
	}

	return nil
}

func validatePermissionError(err error) error {
	switch {
	case err == nil:
		return errors.New("no error returned")
	case status.Code(err) != codes.PermissionDenied:
		return fmt.Errorf("unnexpected error returned: %v", err)
	default:
		return nil
	}
}
