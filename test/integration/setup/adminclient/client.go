package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/url"
	"reflect"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/test/integration/setup/itclient"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	testBundle = `
-----BEGIN CERTIFICATE-----
MIICOTCCAZqgAwIBAgIBATAKBggqhkjOPQQDBDAeMQswCQYDVQQGEwJVUzEPMA0G
A1UECgwGU1BJRkZFMB4XDTE4MDIxMDAwMzQ0NVoXDTE4MDIxMDAxMzQ1NVowHjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBlNQSUZGRTCBmzAQBgcqhkjOPQIBBgUrgQQA
IwOBhgAEAZ6nXrNctKHNjZT7ZkP7xwfpMfvc/DAHc39GdT3qi8mmowY0/XuFQmlJ
cXXwv8ZlOSoGvtuLAEx1lvHNZwv4BuuPALILcIW5tyC8pjcbfqs8PMQYwiC+oFKH
BTxXzolpLeHuFLAD9ccfwWhkT1z/t4pvLkP4FCkkBosG9PVg5JQVJuZJo4GFMIGC
MA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBT4RuNt
x6E70yjV0wIvUyrGkMKczzAfBgNVHSMEGDAWgBRGyozl9Mjue0Y3w4c2Q+3u+wVk
CjAfBgNVHREEGDAWhhRzcGlmZmU6Ly9leGFtcGxlLm9yZzAKBggqhkjOPQQDBAOB
jAAwgYgCQgHOtx4sNCioAQnpEx3J/A9M6Lutth/ND/h8D+7luqEkd4tMrBQgnMj4
E0xLGUNtoFNRIrEUlgwksWvKZ3BksIIOMwJCAc8VPA/QYrlJDeQ58FKyQyrOIlPk
Q0qBJEOkL6FrAngY5218TCNUS30YS5HjI2lfyyjB+cSVFXX8Szu019dDBMhV
-----END CERTIFICATE-----
`
)

var (
	blk, _       = pem.Decode([]byte(testBundle))
	pkixBytes, _ = base64.StdEncoding.DecodeString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYSlUVLqTD8DEnA4F1EWMTf5RXc5lnCxw+5WKJwngEL3rPc9i4Tgzz9riR3I/NiSlkgRO1WsxBusqpC284j9dXA==")
	key, _       = pemutil.ParseSigner([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgs/CcKxAEIyBBEQ9h
ES2kJbWTz79ut45qAb0UgqrGqmOhRANCAARssWdfmS3D4INrpLBdSBxzso5kPPSX
F21JuznwCuYKNV5LnzhUA3nt2+6e18ZIXUDxl+CpkvCYc10MO6SYg6AE
-----END PRIVATE KEY-----`))
	// Used between test
	entryID = ""
	agentID = &types.SPIFFEID{}
)

func main() {
	if msg := run(); msg != "" {
		log.Fatal(msg)
	}
	log.Println("Admin client finished successfully")
}

// run execute all test cases return true if all test cases finished successfully
func run() string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	c := itclient.New(ctx)
	defer c.Release()

	type failure struct {
		name string
		err  error
	}

	var failures []failure
	testRPC := func(rpcName string, rpcFn func(context.Context, *itclient.Client) error) {
		if rpcErr := rpcFn(ctx, c); rpcErr != nil {
			failures = append(failures, failure{
				name: rpcName,
				err:  rpcErr,
			})
		}
	}

	// SVID Client tests
	testRPC("MintX509SVID", mintX509SVID)
	testRPC("MintJWTSVID", mintJWTSVID)
	// Bundle Client tests
	testRPC("AppendBundle", appendBundle)
	testRPC("BatchCreateFederatedBundle", batchCreateFederatedBundle)
	testRPC("BatchUpdateFederatedBundle", batchUpdateFederatedBundle)
	testRPC("BatchSetFederatedBundle", batchSetFederatedBundle)
	testRPC("CountBundles", countBundles)
	testRPC("ListFederatedBundles", listFederatedBundles)
	testRPC("GetFederatedBundle", getFederatedBundle)
	testRPC("BatchDeleteFederatedBundle", batchDeleteFederatedBundle)
	// Entry client tests
	testRPC("BatchCreateEntry", batchCreateEntry)
	testRPC("CountEntries", countEntries)
	testRPC("ListEntries", listEntries)
	testRPC("GetEntry", getEntry)
	testRPC("BatchUpdateEntry", batchUpdateEntry)
	testRPC("BatchDeleteEntry", batchDeleteEntry)
	// Agent client tests
	testRPC("CreateJoinToken", createJoinToken)
	testRPC("CountAgents", countAgents)
	testRPC("ListAgents", listAgents)
	testRPC("GetAgent", getAgent)
	testRPC("BanAgent", banAgent)
	testRPC("DeleteAgent", deleteAgent)
	// Trustdomain client tests
	testRPC("BatchCreateFederationRelationship", batchCreateFederationRelationship)
	testRPC("BatchUpdateFederationRelationship", batchUpdateFederationRelationship)
	testRPC("GetFederationRelationship", getFederationRelationship)
	testRPC("ListFederationRelationships", listFederationRelationships)
	testRPC("BatchDeleteFederationRelationship", batchDeleteFederationRelationship)

	msg := ""
	for _, failure := range failures {
		msg += fmt.Sprintf("RPC %q: %v\n", failure.name, failure.err)
	}

	return msg
}

func mintX509SVID(ctx context.Context, c *itclient.Client) error {
	id := spiffeid.RequireFromPath(c.Td, "/new_workload")

	expectedID := &types.SPIFFEID{
		TrustDomain: id.TrustDomain().String(),
		Path:        id.Path(),
	}

	// Create CSR
	template := &x509.CertificateRequest{URIs: []*url.URL{id.URL()}}
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	// Call mint
	resp, err := c.SVIDClient().MintX509SVID(ctx, &svidv1.MintX509SVIDRequest{
		Csr: csr,
	})
	// Validate error
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case time.Unix(resp.Svid.ExpiresAt, 0).Before(time.Now()):
		return errors.New("invalid ExpiresAt")
	case !proto.Equal(resp.Svid.Id, expectedID):
		return fmt.Errorf("unexpected Id: %v", resp.Svid.Id.String())
	case len(resp.Svid.CertChain) == 0:
		return errors.New("empty CertChain")
	}

	// Validate certificate
	cert, err := x509.ParseCertificate(resp.Svid.CertChain[0])
	if err != nil {
		return fmt.Errorf("unable to parse cert: %w", err)
	}

	certPool := x509.NewCertPool()
	for _, chain := range resp.Svid.CertChain {
		b, err := x509.ParseCertificate(chain)
		if err != nil {
			return fmt.Errorf("unable to parse bundle: %w", err)
		}
		certPool.AddCert(b)
	}

	_, err = cert.Verify(x509.VerifyOptions{
		Roots: certPool,
	})

	return err
}

func mintJWTSVID(ctx context.Context, c *itclient.Client) error {
	id := &types.SPIFFEID{TrustDomain: c.Td.String(), Path: "/new_workload"}
	resp, err := c.SVIDClient().MintJWTSVID(ctx, &svidv1.MintJWTSVIDRequest{
		Id:       id,
		Audience: []string{"myAud"},
	})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case !proto.Equal(resp.Svid.Id, id):
		return fmt.Errorf("unexpected Id: %v", resp.Svid.Id.String())
	case time.Unix(resp.Svid.ExpiresAt, 0).Before(time.Now()):
		return errors.New("jwt SVID is expired")
	}

	// Parse token
	token, err := jwt.ParseSigned(resp.Svid.Token)
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}
	claimsMap := make(map[string]interface{})
	err = token.UnsafeClaimsWithoutVerification(&claimsMap)
	if err != nil {
		return fmt.Errorf("claims verification failed: %w", err)
	}

	// Validate token
	switch {
	case claimsMap["aud"] == nil:
		return errors.New("missing aud")
	case fmt.Sprintf("%v", claimsMap["aud"]) != "[myAud]":
		return fmt.Errorf("uexpected aud %v", claimsMap["aud"])
	case claimsMap["exp"] == 0:
		return errors.New("missing exp")
	case claimsMap["iat"] == 0:
		return errors.New("missing iat")
	case claimsMap["sub"] != fmt.Sprintf("spiffe://%s/new_workload", c.Td.String()):
		return fmt.Errorf("unexpected sub: %q, %s", claimsMap["sub"], fmt.Sprintf("spiffe://%q/new_workload", c.Td))
	}

	return nil
}

func appendBundle(ctx context.Context, c *itclient.Client) error {
	jwtKey := &types.JWTKey{
		PublicKey: pkixBytes,
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
		KeyId:     "authority1",
	}

	resp, err := c.BundleClient().AppendBundle(ctx, &bundlev1.AppendBundleRequest{
		X509Authorities: []*types.X509Certificate{{Asn1: blk.Bytes}},
		JwtAuthorities:  []*types.JWTKey{jwtKey},
	})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case resp.TrustDomain != c.Td.String():
		return fmt.Errorf("unexpected td: %v", resp.TrustDomain)
	case len(resp.JwtAuthorities) == 0:
		return errors.New("missing JWT authorities")
	case len(resp.X509Authorities) == 0:
		return errors.New("missing X509 authorities")
	case !containsX509Certificate(resp.X509Authorities, blk.Bytes):
		return errors.New("no append x509 authority")
	case !containsJWTKey(resp.JwtAuthorities, jwtKey):
		return errors.New("no append jwt key")
	}

	return nil
}

func batchCreateFederatedBundle(ctx context.Context, c *itclient.Client) error {
	jwtKey := &types.JWTKey{
		PublicKey: pkixBytes,
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
		KeyId:     "authority1",
	}
	resp, err := c.BundleClient().BatchCreateFederatedBundle(ctx, &bundlev1.BatchCreateFederatedBundleRequest{
		Bundle: []*types.Bundle{
			{
				TrustDomain:     "foo",
				JwtAuthorities:  []*types.JWTKey{jwtKey},
				X509Authorities: []*types.X509Certificate{{Asn1: blk.Bytes}},
			},
		},
	})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case len(resp.Results) != 1:
		return fmt.Errorf("unexpected response size: %d", len(resp.Results))
	}

	// Validate result
	r := resp.Results[0]
	switch {
	case r.Status.Code != int32(codes.OK):
		return fmt.Errorf("unexpected status: %v", r.Status)
	case r.Bundle.TrustDomain != "foo":
		return fmt.Errorf("unexpected trust domain: %q", r.Bundle.TrustDomain)
	case len(r.Bundle.JwtAuthorities) == 0:
		return errors.New("missing JWT authorities")
	case len(r.Bundle.X509Authorities) == 0:
		return errors.New("missing X509 authorities")
	case !containsX509Certificate(r.Bundle.X509Authorities, blk.Bytes):
		return errors.New("no X509 authority")
	case !containsJWTKey(r.Bundle.JwtAuthorities, jwtKey):
		return errors.New("no JWT key")
	}

	return nil
}

func batchUpdateFederatedBundle(ctx context.Context, c *itclient.Client) error {
	jwtKey := &types.JWTKey{
		PublicKey: pkixBytes,
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
		KeyId:     "authority2",
	}
	resp, err := c.BundleClient().BatchUpdateFederatedBundle(ctx, &bundlev1.BatchUpdateFederatedBundleRequest{
		Bundle: []*types.Bundle{
			{
				TrustDomain:    "foo",
				JwtAuthorities: []*types.JWTKey{jwtKey},
			},
		},
	})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case len(resp.Results) != 1:
		return fmt.Errorf("unexpected response size: %d", len(resp.Results))
	}

	r := resp.Results[0]
	switch {
	case r.Status.Code != int32(codes.OK):
		return fmt.Errorf("unexpected status: %v", r.Status)
	case r.Bundle.TrustDomain != "foo":
		return fmt.Errorf("unexpected trust domain: %q", r.Bundle.TrustDomain)
	case len(r.Bundle.JwtAuthorities) == 0:
		return errors.New("missing JWT authorities")
	case len(r.Bundle.X509Authorities) != 0:
		return errors.New("unexpected x509 authorities")
	case !containsJWTKey(r.Bundle.JwtAuthorities, jwtKey):
		return errors.New("no updated jwt key")
	}

	return nil
}

func batchSetFederatedBundle(ctx context.Context, c *itclient.Client) error {
	jwtKey := &types.JWTKey{
		PublicKey: pkixBytes,
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
		KeyId:     "authority1",
	}
	resp, err := c.BundleClient().BatchSetFederatedBundle(ctx, &bundlev1.BatchSetFederatedBundleRequest{
		Bundle: []*types.Bundle{
			{
				TrustDomain:     "bar",
				JwtAuthorities:  []*types.JWTKey{jwtKey},
				X509Authorities: []*types.X509Certificate{{Asn1: blk.Bytes}},
			},
		},
	})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case len(resp.Results) != 1:
		return fmt.Errorf("unexpected response size: %d", len(resp.Results))
	}

	// Validate result
	r := resp.Results[0]
	switch {
	case r.Status.Code != int32(codes.OK):
		return fmt.Errorf("unexpected status: %v", r.Status)
	case r.Bundle.TrustDomain != "bar":
		return fmt.Errorf("unexpected trust domain: %q", r.Bundle.TrustDomain)
	case len(r.Bundle.JwtAuthorities) == 0:
		return errors.New("missing JWT authorities")
	case len(r.Bundle.X509Authorities) == 0:
		return errors.New("missing X509 authorities")
	case !containsX509Certificate(r.Bundle.X509Authorities, blk.Bytes):
		return errors.New("no X509 authority")
	case !containsJWTKey(r.Bundle.JwtAuthorities, jwtKey):
		return errors.New("no JWT key")
	}

	return nil
}

func countBundles(ctx context.Context, c *itclient.Client) error {
	resp, err := c.BundleClient().CountBundles(ctx, &bundlev1.CountBundlesRequest{})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case resp.Count != 4:
		return fmt.Errorf("unexpected bundle count: %d", resp.Count)
	}
	return nil
}

func listFederatedBundles(ctx context.Context, c *itclient.Client) error {
	resp, err := c.BundleClient().ListFederatedBundles(ctx, &bundlev1.ListFederatedBundlesRequest{})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case len(resp.Bundles) != 3:
		return fmt.Errorf("unexpected bundles size: %d", len(resp.Bundles))
	}

	containsFunc := func(td string) bool {
		for _, b := range resp.Bundles {
			if b.TrustDomain == td {
				return true
			}
		}
		return false
	}

	for _, td := range []string{"foo", "bar"} {
		if !containsFunc(td) {
			return fmt.Errorf("bundle for trust domain %q not found", td)
		}
	}
	return nil
}

func getFederatedBundle(ctx context.Context, c *itclient.Client) error {
	resp, err := c.BundleClient().GetFederatedBundle(ctx, &bundlev1.GetFederatedBundleRequest{
		TrustDomain: "bar",
	})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case resp.TrustDomain != "bar":
		return fmt.Errorf("unexpected trust domain: %q", resp.TrustDomain)
	case len(resp.JwtAuthorities) == 0:
		return errors.New("missing JWT authorities")
	case len(resp.X509Authorities) == 0:
		return errors.New("missing X509 authorities")
	}

	return nil
}

func batchDeleteFederatedBundle(ctx context.Context, c *itclient.Client) error {
	deleteList := []string{"foo", "bar"}
	resp, err := c.BundleClient().BatchDeleteFederatedBundle(ctx, &bundlev1.BatchDeleteFederatedBundleRequest{
		TrustDomains: deleteList,
	})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	}

	for i, r := range resp.Results {
		switch {
		case r.Status.Code != int32(codes.OK):
			return fmt.Errorf("unexpected status: %v", r.Status)
		case r.TrustDomain != deleteList[i]:
			return fmt.Errorf("unexpected trust domain: %q", r.TrustDomain)
		}
	}
	return nil
}

func batchCreateEntry(ctx context.Context, c *itclient.Client) error {
	testEntry := &types.Entry{
		ParentId: &types.SPIFFEID{
			TrustDomain: c.Td.String(),
			Path:        "/foo",
		},
		SpiffeId: &types.SPIFFEID{
			TrustDomain: c.Td.String(),
			Path:        "/bar",
		},
		Selectors: []*types.Selector{
			{
				Type:  "unix",
				Value: "uid:1001",
			},
		},
	}
	resp, err := c.EntryClient().BatchCreateEntry(ctx, &entryv1.BatchCreateEntryRequest{
		Entries: []*types.Entry{testEntry},
	})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case len(resp.Results) != 1:
		return fmt.Errorf("unexpected response size: %d", len(resp.Results))
	}

	// Validate result
	r := resp.Results[0]
	testEntry.Id = r.Entry.Id
	if r.Entry != nil {
		testEntry.CreatedAt = r.Entry.CreatedAt
	}
	switch {
	case r.Status.Code != int32(codes.OK):
		return fmt.Errorf("unexpected status: %v", r.Status)
	case !proto.Equal(r.Entry, testEntry):
		return fmt.Errorf("unexpected entry: %v", r.Entry)
	}

	// Setup entry ID it will be used for another tests
	entryID = r.Entry.Id
	return nil
}

func countEntries(ctx context.Context, c *itclient.Client) error {
	resp, err := c.EntryClient().CountEntries(ctx, &entryv1.CountEntriesRequest{})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case resp.Count < 3:
		return fmt.Errorf("unexpected entry count: %d", resp.Count)
	}
	return nil
}

func listEntries(ctx context.Context, c *itclient.Client) error {
	expectedSpiffeIDs := []*types.SPIFFEID{
		{TrustDomain: c.Td.String(), Path: "/admin"},
		{TrustDomain: c.Td.String(), Path: "/agent-alias"},
		{TrustDomain: c.Td.String(), Path: "/workload"},
		{TrustDomain: c.Td.String(), Path: "/bar"},
	}
	resp, err := c.EntryClient().ListEntries(ctx, &entryv1.ListEntriesRequest{})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case len(resp.Entries) < 3:
		return fmt.Errorf("unexpected entries size: %d", len(resp.Entries))
	}

	containsFunc := func(id *types.SPIFFEID) bool {
		for _, expected := range expectedSpiffeIDs {
			if proto.Equal(expected, id) {
				return true
			}
		}
		return false
	}

	for _, e := range resp.Entries {
		if !containsFunc(e.SpiffeId) {
			return fmt.Errorf("unexpected entry: %v", e.SpiffeId)
		}
	}

	return nil
}

func getEntry(ctx context.Context, c *itclient.Client) error {
	testEntry := &types.Entry{
		Id: entryID,
		ParentId: &types.SPIFFEID{
			TrustDomain: c.Td.String(),
			Path:        "/foo",
		},
		SpiffeId: &types.SPIFFEID{
			TrustDomain: c.Td.String(),
			Path:        "/bar",
		},
		Selectors: []*types.Selector{
			{
				Type:  "unix",
				Value: "uid:1001",
			},
		},
	}
	resp, err := c.EntryClient().GetEntry(ctx, &entryv1.GetEntryRequest{
		Id: entryID,
	})
	if resp != nil {
		testEntry.CreatedAt = resp.CreatedAt
	}

	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case !proto.Equal(resp, testEntry):
		return fmt.Errorf("unexpected entry: %v", resp)
	}

	return nil
}

func batchUpdateEntry(ctx context.Context, c *itclient.Client) error {
	testEntry := &types.Entry{
		Id: entryID,
		ParentId: &types.SPIFFEID{
			TrustDomain: c.Td.String(),
			Path:        "/foo",
		},
		SpiffeId: &types.SPIFFEID{
			TrustDomain: c.Td.String(),
			Path:        "/bar",
		},
		Selectors: []*types.Selector{
			{
				Type:  "unix",
				Value: "uid:1001",
			},
			{
				Type:  "unix",
				Value: "uid:1002",
			},
		},
		DnsNames:       []string{"dns1"},
		RevisionNumber: 1,
	}
	resp, err := c.EntryClient().BatchUpdateEntry(ctx, &entryv1.BatchUpdateEntryRequest{
		Entries: []*types.Entry{testEntry},
	})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case len(resp.Results) != 1:
		return fmt.Errorf("unexpected response size: %d", len(resp.Results))
	}

	// Validate result
	r := resp.Results[0]
	if r.Entry != nil {
		testEntry.CreatedAt = r.Entry.CreatedAt
	}

	switch {
	case r.Status.Code != int32(codes.OK):
		return fmt.Errorf("unexpected status: %v", r.Status)
	case !proto.Equal(r.Entry, testEntry):
		return fmt.Errorf("unexpected entry: %v", r.Entry)
	}
	return nil
}

func batchDeleteEntry(ctx context.Context, c *itclient.Client) error {
	resp, err := c.EntryClient().BatchDeleteEntry(ctx, &entryv1.BatchDeleteEntryRequest{
		Ids: []string{entryID},
	})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case len(resp.Results) != 1:
		return fmt.Errorf("unexpected response size: %d", len(resp.Results))
	}

	// Validate result
	r := resp.Results[0]
	switch {
	case r.Status.Code != int32(codes.OK):
		return fmt.Errorf("unexpected status: %v", r.Status)
	case r.Id != entryID:
		return fmt.Errorf("unexpected entry: %v", r)
	}
	return nil
}

func createJoinToken(ctx context.Context, c *itclient.Client) error {
	id := &types.SPIFFEID{
		TrustDomain: c.Td.String(),
		Path:        "/agent-alias",
	}

	resp, err := c.AgentClient().CreateJoinToken(ctx, &agentv1.CreateJoinTokenRequest{
		AgentId: id,
		Ttl:     60,
	})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case resp.ExpiresAt == 0:
		return errors.New("missing expiration")
	case resp.Value == "":
		return errors.New("missing token")
	}

	// Set agentID that will be used in other tests
	agentID = &types.SPIFFEID{
		TrustDomain: c.Td.String(),
		Path:        fmt.Sprintf("/spire/agent/join_token/%s", resp.Value),
	}

	// Create CSR
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	// Attest using generated token
	stream, err := c.AgentClient().AttestAgent(ctx)
	if err != nil {
		return err
	}

	err = stream.Send(&agentv1.AttestAgentRequest{
		Step: &agentv1.AttestAgentRequest_Params_{Params: &agentv1.AttestAgentRequest_Params{
			Data: &types.AttestationData{
				Type:    "join_token",
				Payload: []byte(resp.Value),
			},
			Params: &agentv1.AgentX509SVIDParams{
				Csr: csr,
			},
		}},
	})
	if err != nil {
		return err
	}
	_, err = stream.Recv()
	if err != nil {
		return err
	}

	return nil
}

func countAgents(ctx context.Context, c *itclient.Client) error {
	resp, err := c.AgentClient().CountAgents(ctx, &agentv1.CountAgentsRequest{})

	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case resp.Count != 2:
		return fmt.Errorf("unexpected agent count: %d", resp.Count)
	}
	return nil
}

func listAgents(ctx context.Context, c *itclient.Client) error {
	resp, err := c.AgentClient().ListAgents(ctx, &agentv1.ListAgentsRequest{
		Filter: &agentv1.ListAgentsRequest_Filter{
			ByAttestationType: "join_token",
		},
	})

	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case len(resp.Agents) != 1:
		return fmt.Errorf("only one agent is expected")
	}

	// Validate agent
	a := resp.Agents[0]
	switch {
	case a.AttestationType != "join_token":
		return fmt.Errorf("unexpected attestation type: %q", a.AttestationType)
	case a.Banned:
		return errors.New("agent is banned")
	case !proto.Equal(a.Id, agentID):
		return fmt.Errorf("unexpected ID: %q", a.Id)
	}
	return nil
}

func getAgent(ctx context.Context, c *itclient.Client) error {
	resp, err := c.AgentClient().GetAgent(ctx, &agentv1.GetAgentRequest{
		Id: agentID,
	})

	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case resp.AttestationType != "join_token":
		return fmt.Errorf("unexpected attestation type: %q", resp.AttestationType)
	case resp.Banned:
		return errors.New("agent is banned")
	case !proto.Equal(resp.Id, agentID):
		return fmt.Errorf("unexpected ID: %q", resp.Id)
	}
	return nil
}

func banAgent(ctx context.Context, c *itclient.Client) error {
	// Ban agent returns empty as response
	_, err := c.AgentClient().BanAgent(ctx, &agentv1.BanAgentRequest{
		Id: agentID,
	})

	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	}

	// Validates it is banned
	r, err := c.AgentClient().GetAgent(ctx, &agentv1.GetAgentRequest{
		Id: agentID,
	})
	if err != nil {
		return fmt.Errorf("failed to get agent: %w", err)
	}
	if !r.Banned {
		return errors.New("agent is not banned")
	}
	return nil
}

func deleteAgent(ctx context.Context, c *itclient.Client) error {
	// Delete agent returns empty as response
	_, err := c.AgentClient().DeleteAgent(ctx, &agentv1.DeleteAgentRequest{
		Id: agentID,
	})

	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	}

	// Validates it is banned
	_, err = c.AgentClient().GetAgent(ctx, &agentv1.GetAgentRequest{
		Id: agentID,
	})
	if status.Code(err) != codes.NotFound {
		return errors.New("not found status expected")
	}
	return nil
}

func batchCreateFederationRelationship(ctx context.Context, c *itclient.Client) error {
	fr := &types.FederationRelationship{
		TrustDomain:           "federated.test",
		BundleEndpointUrl:     "https://federated.test/endpoint",
		BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{HttpsWeb: &types.HTTPSWebProfile{}},
	}
	resp, err := c.TrustDomainClient().BatchCreateFederationRelationship(ctx, &trustdomain.BatchCreateFederationRelationshipRequest{
		FederationRelationships: []*types.FederationRelationship{fr},
	})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case len(resp.Results) != 1:
		return errors.New("only one relationship expected")
	}

	// Validate result
	r := resp.Results[0]
	switch {
	case r.Status.Code != int32(codes.OK):
		return fmt.Errorf("unexpected status: %v", r.Status)
	case r.FederationRelationship.TrustDomain != "federated.test":
		return fmt.Errorf("unexpected trust domain: %q", r.FederationRelationship.TrustDomain)
	case r.FederationRelationship.BundleEndpointUrl != "https://federated.test/endpoint":
		return fmt.Errorf("unexpected bundle endpoint: %q", r.FederationRelationship.BundleEndpointUrl)
	}

	if _, ok := r.FederationRelationship.BundleEndpointProfile.(*types.FederationRelationship_HttpsWeb); !ok {
		return errors.New("unexpected profile type")
	}

	return nil
}

func batchUpdateFederationRelationship(ctx context.Context, c *itclient.Client) error {
	fr := &types.FederationRelationship{
		TrustDomain:           "federated.test",
		BundleEndpointUrl:     "https://federated.test/endpointupdated",
		BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{HttpsWeb: &types.HTTPSWebProfile{}},
	}
	resp, err := c.TrustDomainClient().BatchUpdateFederationRelationship(ctx, &trustdomain.BatchUpdateFederationRelationshipRequest{
		FederationRelationships: []*types.FederationRelationship{fr},
	})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case len(resp.Results) != 1:
		return errors.New("only one relationship expected")
	}

	r := resp.Results[0]
	switch {
	case r.Status.Code != int32(codes.OK):
		return fmt.Errorf("unexpected status: %v", r.Status)
	case r.FederationRelationship.TrustDomain != "federated.test":
		return fmt.Errorf("unexpected trust domain: %q", r.FederationRelationship.TrustDomain)
	case r.FederationRelationship.BundleEndpointUrl != "https://federated.test/endpointupdated":
		return fmt.Errorf("unexpected bundle endpoint: %q", r.FederationRelationship.BundleEndpointUrl)
	}

	if _, ok := r.FederationRelationship.BundleEndpointProfile.(*types.FederationRelationship_HttpsWeb); !ok {
		return errors.New("unexpected profile type")
	}

	return nil
}

func listFederationRelationships(ctx context.Context, c *itclient.Client) error {
	resp, err := c.TrustDomainClient().ListFederationRelationships(ctx, &trustdomain.ListFederationRelationshipsRequest{})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case len(resp.FederationRelationships) != 1:
		return errors.New("only one relationship expected")
	}

	return nil
}

func getFederationRelationship(ctx context.Context, c *itclient.Client) error {
	resp, err := c.TrustDomainClient().GetFederationRelationship(ctx, &trustdomain.GetFederationRelationshipRequest{
		TrustDomain: "federated.test",
	})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case resp.TrustDomain != "federated.test":
		return fmt.Errorf("unexpected trut domain: %q", resp.TrustDomain)
	}

	return nil
}

func batchDeleteFederationRelationship(ctx context.Context, c *itclient.Client) error {
	resp, err := c.TrustDomainClient().BatchDeleteFederationRelationship(ctx, &trustdomain.BatchDeleteFederationRelationshipRequest{
		TrustDomains: []string{"federated.test"},
	})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return err
	case len(resp.Results) != 1:
		return errors.New("only one relationship expected")
	}

	r := resp.Results[0]
	switch {
	case r.Status.Code != int32(codes.OK):
		return fmt.Errorf("unexpected status: %v", r.Status)
	case r.TrustDomain != "federated.test":
		return fmt.Errorf("unexpected trust domain: %q", r.TrustDomain)
	}

	return nil
}

func validatePermissionError(err error) error {
	switch {
	case err == nil:
		return errors.New("no error returned")
	case status.Code(err) != codes.PermissionDenied:
		return fmt.Errorf("unnexpected error returned: %w", err)
	default:
		return nil
	}
}

func containsX509Certificate(certs []*types.X509Certificate, b []byte) bool {
	for _, c := range certs {
		if reflect.DeepEqual(c.Asn1, b) {
			return true
		}
	}
	return false
}

func containsJWTKey(keys []*types.JWTKey, key *types.JWTKey) bool {
	for _, k := range keys {
		if proto.Equal(k, key) {
			return true
		}
	}
	return false
}
