package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"time"

	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/test/integration/setup/itclient"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

var (
	key, _ = pemutil.ParseSigner([]byte(`
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgs/CcKxAEIyBBEQ9h
ES2kJbWTz79ut45qAb0UgqrGqmOhRANCAARssWdfmS3D4INrpLBdSBxzso5kPPSX
F21JuznwCuYKNV5LnzhUA3nt2+6e18ZIXUDxl+CpkvCYc10MO6SYg6AE
-----END PRIVATE KEY-----
`))
)

func main() {
	// Run all tests cases and if error msg is returned make client fails
	if msg := run(); msg != "" {
		log.Fatal(msg)
	}
	log.Println("Downstream client finished successfully")
}

// run executes all tests cases and return error msg when failing
func run() string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := itclient.New(ctx)
	defer c.Release()

	failures := make(map[string]error)

	// Validate call to New Downstream X509 CA
	if err := validateNewDownstreamX509CA(ctx, c); err != nil {
		failures["NewDownstreamX509CA"] = err
	}

	if err := validatePublishJWTAUthorirty(ctx, c); err != nil {
		failures["PublishJWTAuthority"] = err
	}

	msg := ""
	for rpcName, err := range failures {
		msg += fmt.Sprintf("RPC %q: %v\n", rpcName, err)
	}

	return msg
}

func validateNewDownstreamX509CA(ctx context.Context, c *itclient.Client) error {
	// Create csr
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	// Create new svid client and new downstream CA
	resp, err := c.SVIDClient().NewDownstreamX509CA(ctx, &svidv1.NewDownstreamX509CARequest{
		Csr: csr,
	})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return fmt.Errorf("failed to call NewDownstreamX509CA: %w", err)
	case len(resp.CaCertChain) == 0:
		return errors.New("no CA returned")
	case len(resp.X509Authorities) == 0:
		return errors.New("no authorities returned")
	}

	return nil
}

func validatePublishJWTAUthorirty(ctx context.Context, c *itclient.Client) error {
	// Marshal key
	pkixBytes, err := base64.StdEncoding.DecodeString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYSlUVLqTD8DEnA4F1EWMTf5RXc5lnCxw+5WKJwngEL3rPc9i4Tgzz9riR3I/NiSlkgRO1WsxBusqpC284j9dXA==")
	if err != nil {
		return fmt.Errorf("unable to marshal key: %w", err)
	}

	jwtKey := &types.JWTKey{
		PublicKey: pkixBytes,
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
		KeyId:     "authority1",
	}
	resp, err := c.BundleClient().PublishJWTAuthority(ctx, &bundlev1.PublishJWTAuthorityRequest{
		JwtAuthority: jwtKey,
	})
	switch {
	case c.ExpectErrors:
		return validatePermissionError(err)
	case err != nil:
		return fmt.Errorf("failed to publish JWT authority: %w", err)
	case len(resp.JwtAuthorities) == 0:
		return errors.New("no authorities ruturned")
	}

	for _, a := range resp.JwtAuthorities {
		if proto.Equal(jwtKey, a) {
			// Authority appended
			return nil
		}
	}
	return errors.New("authority was not added")
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
