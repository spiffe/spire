package upstreamca

import (
	"context"
	"crypto/x509"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamca"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "myupstreamca"
)

// Config contains the configuration fields for the plugin.
type Config struct {
	ExampleString string `hcl:"example_string"`
}

// MyUpstreamCA implements the upstream.Plugin interface.
type MyUpstreamCA struct {
}

func New() *MyUpstreamCA {
	return &MyUpstreamCA{}
}

// SetLogger is an optional method. If present, the plugin loading code will
// provide your plugin implementation with a logger wired up to
// the SPIRE logger.
func (p *MyUpstreamCA) SetLogger(logger hclog.Logger) {
}

func (p *MyUpstreamCA) SubmitCSR(ctx context.Context, req *upstreamca.SubmitCSRRequest) (*upstreamca.SubmitCSRResponse, error) {
	// TODO: parse and sign the CSR

	// bundle contains the upstream trust bundle.
	var bundle []*x509.Certificate

	// certChain the newly signed certificate and any intermediates necessary
	// to chain back to a certificate in bundle.
	var certChain []*x509.Certificate

	return &upstreamca.SubmitCSRResponse{
		SignedCertificate: &upstreamca.SignedCertificate{
			CertChain: certsToDER(certChain),
			Bundle:    certsToDER(bundle),
		},
	}, nil
}

func (p *MyUpstreamCA) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	// Parse HCL configuration, if you need any
	c := new(Config)
	if err := hcl.Decode(c, req.Configuration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to parse configuration: %v", err)
	}

	// Do something with your configuration
	c = c
	return &spi.ConfigureResponse{}, nil
}

func (p *MyUpstreamCA) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	// currently unused by SPIRE
	return &spi.GetPluginInfoResponse{}, nil
}

func certsToDER(certs []*x509.Certificate) []byte {
	var derBytes []byte
	for _, cert := range certs {
		derBytes = append(derBytes, cert.Raw...)
	}
	return derBytes
}

// If you are implementing an external plugin, you can use the following main()
// to run your plugin.
//func main() {
//	plugin := New()
//	catalog.PluginMain(
//		catalog.MakePlugin(pluginName, upstreamca.PluginServer(plugin)),
//	)
//}
