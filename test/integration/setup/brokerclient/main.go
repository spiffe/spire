// brokerclient is the e2e test driver for the SPIFFE Broker API. It fetches
// its own SVID from the Workload API, then dials the agent's broker endpoint
// with mTLS and exercises the requested scenario (PID reference, Kubernetes
// object reference). It asserts either a specific SPIFFE ID in the response
// or a specific gRPC error code.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

var (
	workloadAPIAddr = flag.String("workload-api", "unix:///run/spire/agent-sockets/api.sock", "Workload API socket URI")
	brokerAddr      = flag.String("broker-addr", "unix:///run/spire/broker-sockets/broker.sock", "Broker API socket URI")
	trustDomain     = flag.String("trust-domain", "example.org", "Trust domain to authorize when dialing the broker")
	refType         = flag.String("ref-type", "", "Reference type: pid|object")
	pid             = flag.Int("pid", 0, "PID for pid reference")
	plural          = flag.String("plural", "", "K8s resource plural (e.g. pods, deployments, kustomizations)")
	group           = flag.String("group", "", "K8s resource group (e.g. core, apps, kustomize.toolkit.fluxcd.io)")
	namespace       = flag.String("namespace", "", "K8s object namespace")
	name            = flag.String("name", "", "K8s object name")
	uid             = flag.String("uid", "", "K8s object UID")
	expectedSPIFFE  = flag.String("expected-spiffe", "", "Expected SPIFFE ID in the response (omit when expecting an error)")
	expectErr       = flag.String("expect-err", "", "Expected gRPC code (e.g. PermissionDenied, Unavailable)")
	skipBrokerDial  = flag.Bool("skip-broker", false, "Only verify Workload API fetches an SVID; do not call the broker API")
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		log.Fatalf("brokerclient: %v", err)
	}
	log.Print("brokerclient: OK")
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	src, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(*workloadAPIAddr)),
	)
	if err != nil {
		return fmt.Errorf("workload API: %w", err)
	}
	defer src.Close()

	own, err := src.GetX509SVID()
	if err != nil {
		return fmt.Errorf("get own SVID: %w", err)
	}
	log.Printf("own SPIFFE ID: %s", own.ID)

	if *skipBrokerDial {
		return nil
	}

	req, err := buildRequest()
	if err != nil {
		return err
	}

	td, err := spiffeid.TrustDomainFromString(*trustDomain)
	if err != nil {
		return fmt.Errorf("parse trust domain: %w", err)
	}
	tlsCfg := tlsconfig.MTLSClientConfig(src, src, tlsconfig.AuthorizeMemberOf(td))

	conn, err := grpc.NewClient(*brokerAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		return fmt.Errorf("dial broker: %w", err)
	}
	defer conn.Close()

	client := broker.NewAPIClient(conn)
	ctx = metadata.AppendToOutgoingContext(ctx, "broker.spiffe.io", "true")

	stream, err := client.SubscribeToX509SVID(ctx, req)
	if err != nil {
		return checkErr(err)
	}
	resp, err := stream.Recv()
	if err != nil {
		return checkErr(err)
	}
	return checkResponse(resp)
}

func buildRequest() (*broker.SubscribeToX509SVIDRequest, error) {
	var packed *anypb.Any
	var err error
	switch *refType {
	case "pid":
		packed, err = anypb.New(&broker.WorkloadPIDReference{Pid: int32(*pid)})
	case "object":
		ref := &broker.KubernetesObjectReference{
			Type: &broker.KubernetesObjectType{Plural: *plural, Group: *group},
		}
		if *namespace != "" || *name != "" {
			ref.Key = &broker.KubernetesObjectKey{Namespace: *namespace, Name: *name}
		}
		if *uid != "" {
			ref.Uid = *uid
		}
		packed, err = anypb.New(ref)
	default:
		return nil, fmt.Errorf("unknown ref-type %q", *refType)
	}
	if err != nil {
		return nil, fmt.Errorf("packing reference: %w", err)
	}
	return &broker.SubscribeToX509SVIDRequest{
		Reference: &broker.WorkloadReference{Reference: packed},
	}, nil
}

func checkErr(err error) error {
	code := status.Code(err).String()
	if *expectErr != "" {
		if code == *expectErr {
			log.Printf("got expected error code %s: %v", code, err)
			return nil
		}
		return fmt.Errorf("expected error code %s, got %s (%w)", *expectErr, code, err)
	}
	return fmt.Errorf("unexpected error (code %s): %w", code, err)
}

func checkResponse(resp *broker.SubscribeToX509SVIDResponse) error {
	if *expectErr != "" {
		return fmt.Errorf("expected error %s, but got response with %d SVIDs", *expectErr, len(resp.Svids))
	}
	log.Printf("got %d SVIDs in response", len(resp.Svids))
	if *expectedSPIFFE == "" {
		if len(resp.Svids) == 0 {
			return errors.New("response carried no SVIDs")
		}
		return nil
	}
	for _, svid := range resp.Svids {
		if svid.SpiffeId == *expectedSPIFFE {
			log.Printf("found expected SVID: %s", svid.SpiffeId)
			return nil
		}
	}
	got := []string{}
	for _, svid := range resp.Svids {
		got = append(got, svid.SpiffeId)
	}
	return fmt.Errorf("expected SVID %s, response had: %v", *expectedSPIFFE, got)
}
