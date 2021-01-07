package gcpcas

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	// 	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
)

func TestGCPCAS(t *testing.T) {
	ctx := context.Background()
	fmt.Println("Hi")

	p := New()
	p.SetLogger(hclog.Default())
	_, err := p.Configure(ctx, &plugin.ConfigureRequest{Configuration: `
    root_cert_spec {
        gcp_project_name = "<project-name-here>"
        gcp_region_name = "us-central1"
        label_key = "<label-here>"
        label_value = "label-value-here"
    }

    trust_bundle_cert_spec = [
        {
            gcp_project_name = "<project-name-here>"
            gcp_region_name = "us-central1"
            label_key = "<label-here>"
            label_value = "label-value-here"
        },
        {
            gcp_project_name = "<project-name-here>"
            gcp_region_name = "us-central1"
            label_key = "<label-here>"
            label_value = "label-value-here"
        }
    ]
    `})
	require.NoError(t, err)

	fmt.Printf("%s", p.c)

	validSpiffeID := "spiffe://localhost"
	csr, _, err := util.NewCSRTemplate(validSpiffeID)
	require.NoError(t, err)

	resp, err := p.mintX509CA(ctx, csr, 30)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// 	testCSRResp(s.T(), resp, pubKey, []string{"spiffe://localhost"}, []string{"spiffe://local"})

}
