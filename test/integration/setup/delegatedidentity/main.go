package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	agent_delegatedidentityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/idutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

var (
	socketPathFlag = flag.String("adminSocketPath", "unix:///opt/admin.sock", "admin agent socket path")
	expectedID     = flag.String("expectedID", "", "expected SPIFFE ID for workload")
	expectedTD     string
)

func main() {
	flag.Parse()

	if *expectedID != "" {
		expectedTD = spiffeid.RequireFromString(*expectedID).TrustDomain().IDString()
	}

	if err := run(); err != nil {
		log.Fatalf("Test for Delegated API failed: %v", err)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	conn, err := grpc.NewClient(*socketPathFlag, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to connect server: %w", err)
	}
	defer conn.Close()

	client := agent_delegatedidentityv1.NewDelegatedIdentityClient(conn)

	fetchJWTSVIDsResp, err := client.FetchJWTSVIDs(ctx, &agent_delegatedidentityv1.FetchJWTSVIDsRequest{
		Audience: []string{"audience-1"},
		Selectors: []*types.Selector{
			{
				Type:  "unix",
				Value: "uid:1002",
			},
		},
	})
	if err = validateCode(err); err != nil {
		return fmt.Errorf("error testing FetchJWTSVIDs RPC: %w", err)
	}
	if err := validateFetchJWTSVIDsResponse(fetchJWTSVIDsResp); err != nil {
		return fmt.Errorf("error validating FetchJWTSVIDs RPC response: %w", err)
	}

	streamJWTBundles, err := client.SubscribeToJWTBundles(ctx, &agent_delegatedidentityv1.SubscribeToJWTBundlesRequest{})
	if err != nil {
		return fmt.Errorf("error calling SubscribeToJWTBundles RPC: %w", err)
	}

	subscribeToJWTBundlesResp, err := streamJWTBundles.Recv()
	if err = validateCode(err); err != nil {
		return fmt.Errorf("error receiving from SubscribeToJWTBundles: %w", err)
	}
	if err := validateSubscribeToJWTBundlesResponse(subscribeToJWTBundlesResp); err != nil {
		return fmt.Errorf("error validating SubscribeToJWTBundles response: %w", err)
	}

	streamX509Bundles, err := client.SubscribeToX509Bundles(ctx, &agent_delegatedidentityv1.SubscribeToX509BundlesRequest{})
	if err != nil {
		return fmt.Errorf("error calling SubscribeToX509Bundles RPC: %w", err)
	}

	subscribeToX509BundlesResp, err := streamX509Bundles.Recv()
	if err = validateCode(err); err != nil {
		return fmt.Errorf("error receiving from SubscribeToX509Bundles: %w", err)
	}
	if err := validateSubscribeToX509BundlesResponse(subscribeToX509BundlesResp); err != nil {
		return fmt.Errorf("error validating SubscribeToX509Bundles response: %w", err)
	}

	streamSubscribeToX509SVIDs, err := client.SubscribeToX509SVIDs(ctx, &agent_delegatedidentityv1.SubscribeToX509SVIDsRequest{
		Selectors: []*types.Selector{
			{
				Type:  "unix",
				Value: "uid:1002",
			},
		},
	})
	if err != nil {
		return fmt.Errorf("error calling SubscribeToX509SVIDs RPC: %w", err)
	}
	subscribeToX509SVIDsResp, err := streamSubscribeToX509SVIDs.Recv()
	if err = validateCode(err); err != nil {
		return fmt.Errorf("error receiving from SubscribeToX509SVIDs: %w", err)
	}
	if err := validateSubscribeToX509SVIDsResponse(subscribeToX509SVIDsResp); err != nil {
		return fmt.Errorf("error validating SubscribeToX509SVIDs response: %w", err)
	}

	return nil
}

func validateCode(err error) error {
	switch {
	case *expectedID == "" && status.Code(err) != codes.PermissionDenied:
		return fmt.Errorf("expected to receive PermissionDenied code; but code was: %v", status.Code(err))
	case *expectedID != "" && status.Code(err) != codes.OK:
		return fmt.Errorf("expected to receive OK code; but code was: %v", status.Code(err))
	case status.Code(err) != codes.OK && status.Code(err) != codes.PermissionDenied:
		return fmt.Errorf("unexpected code: %v", status.Code(err))
	}

	return nil
}

func validateFetchJWTSVIDsResponse(resp *agent_delegatedidentityv1.FetchJWTSVIDsResponse) error {
	if *expectedID == "" {
		return nil
	}

	j, err := jwtsvid.ParseInsecure(resp.Svids[0].Token, []string{"audience-1"})
	if err != nil {
		return err
	}
	if j.ID.String() != *expectedID {
		return fmt.Errorf("unexpected SPIFFE ID: %q", j.ID.String())
	}
	return nil
}

func validateSubscribeToJWTBundlesResponse(resp *agent_delegatedidentityv1.SubscribeToJWTBundlesResponse) error {
	if *expectedID == "" {
		return nil
	}

	for td := range resp.Bundles {
		if td != expectedTD {
			return fmt.Errorf("trust domain does not match; expected %q, but was %q", td, expectedTD)
		}
	}

	return nil
}

func validateSubscribeToX509BundlesResponse(resp *agent_delegatedidentityv1.SubscribeToX509BundlesResponse) error {
	if *expectedID == "" {
		return nil
	}

	for td := range resp.CaCertificates {
		if td != expectedTD {
			return fmt.Errorf("error validating SubscribeToJWTBundles response: trust domain does not match; expected %q, but was %q", td, expectedTD)
		}
	}

	return nil
}

func validateSubscribeToX509SVIDsResponse(resp *agent_delegatedidentityv1.SubscribeToX509SVIDsResponse) error {
	if *expectedID == "" {
		return nil
	}

	for _, x509SVIDWithKey := range resp.X509Svids {
		id := idutil.RequireIDFromProto(x509SVIDWithKey.X509Svid.Id).String()
		if id != spiffeid.RequireFromString(*expectedID).String() {
			return fmt.Errorf("the SPIFFE ID does not match; expected %q, but was %q", *expectedID, id)
		}
	}

	return nil
}
