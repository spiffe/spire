package catalog

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type CoreConfig struct {
	TrustDomain spiffeid.TrustDomain
}

func (c CoreConfig) legacy() *spi.ConfigureRequest_GlobalConfig {
	return &spi.ConfigureRequest_GlobalConfig{
		TrustDomain: c.TrustDomain.String(),
	}
}

func (c CoreConfig) v1() *configv1.CoreConfiguration {
	return &configv1.CoreConfiguration{
		TrustDomain: c.TrustDomain.String(),
	}
}

type Configurer interface {
	Configure(ctx context.Context, coreConfig CoreConfig, configuration string) error
}

type configurerRepo struct {
	configurer Configurer
}

func (repo *configurerRepo) Binder() interface{} {
	return func(configurer Configurer) {
		repo.configurer = configurer
	}
}

func (repo *configurerRepo) Versions() []Version {
	return []Version{
		configurerV1Version{},
	}
}

func (repo *configurerRepo) Clear() {
	// This function is only for conforming to the Repo interface and isn't
	// expected to be called, but just in case, we'll do the right thing
	// and clear out the configurer that has been bound.
	repo.configurer = nil
}

type configurerV1Version struct{}

func (configurerV1Version) New() Facade      { return new(configurerV1) }
func (configurerV1Version) Deprecated() bool { return false }

type configurerV1 struct {
	configv1.ConfigServiceClient
}

var _ Configurer = (*configurerV1)(nil)

func (v1 *configurerV1) InitInfo(PluginInfo) {
}

func (v1 *configurerV1) InitLog(logrus.FieldLogger) {
}

func (v1 *configurerV1) Configure(ctx context.Context, coreConfig CoreConfig, hclConfiguration string) error {
	_, err := v1.ConfigServiceClient.Configure(ctx, &configv1.ConfigureRequest{
		CoreConfiguration: coreConfig.v1(),
		HclConfiguration:  hclConfiguration,
	})
	return err
}

type legacyConfigureClient interface {
	Configure(context.Context, *spi.ConfigureRequest, ...grpc.CallOption) (*spi.ConfigureResponse, error)
}

type configurerLegacy struct {
	client legacyConfigureClient
}

func (c configurerLegacy) Configure(ctx context.Context, coreConfig CoreConfig, hclConfiguration string) error {
	_, err := c.client.Configure(ctx, &spi.ConfigureRequest{
		GlobalConfig:  coreConfig.legacy(),
		Configuration: hclConfiguration,
	})
	return err
}

type configurerUnsupported struct{}

func (c configurerUnsupported) Configure(ctx context.Context, coreConfig CoreConfig, hclConfiguration string) error {
	return status.Error(codes.FailedPrecondition, "plugin does not support a configuration interface")
}
