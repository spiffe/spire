package catalog

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

type CoreConfig struct {
	TrustDomain spiffeid.TrustDomain
}

func (c CoreConfig) v1() *configv1.CoreConfiguration {
	return &configv1.CoreConfiguration{
		TrustDomain: c.TrustDomain.Name(),
	}
}

type Configurer interface {
	Configure(ctx context.Context, coreConfig CoreConfig, configuration string) error
	Validate(ctx context.Context, coreConfig CoreConfig, configuration string) (*configv1.ValidateResponse, error)
}

type ConfigurerFunc func(ctx context.Context, coreConfig CoreConfig, configuration string) error
type ValidatorFunc func(ctx context.Context, coreConfig CoreConfig, configuration string) (*configv1.ValidateResponse, error)

func (fn ConfigurerFunc) Configure(ctx context.Context, coreConfig CoreConfig, configuration string) error {
	return fn(ctx, coreConfig, configuration)
}

func (fn ValidatorFunc) Validate(ctx context.Context, coreConfig CoreConfig, configuration string) (*configv1.ValidateResponse, error) {
	return fn(ctx, coreConfig, configuration)
}

func ConfigurePlugin(ctx context.Context, coreConfig CoreConfig, configurer Configurer, dataSource DataSource, lastHash string) (string, error) {
	data, err := dataSource.Load()
	if err != nil {
		return "", fmt.Errorf("failed to load plugin data: %w", err)
	}

	dataHash := hashData(data)
	if lastHash == "" || dataHash != lastHash {
		if err := configurer.Configure(ctx, coreConfig, data); err != nil {
			return "", err
		}
	}
	return dataHash, nil
}

func ReconfigureTask(log logrus.FieldLogger, reconfigurer Reconfigurer) func(context.Context) error {
	return func(ctx context.Context) error {
		return ReconfigureOnSignal(ctx, log, reconfigurer)
	}
}

type Reconfigurer interface {
	Reconfigure(ctx context.Context)
}

type Reconfigurers []Reconfigurer

func (rs Reconfigurers) Reconfigure(ctx context.Context) {
	for _, r := range rs {
		r.Reconfigure(ctx)
	}
}

type Reconfigurable struct {
	Log        logrus.FieldLogger
	CoreConfig CoreConfig
	Configurer Configurer
	DataSource DataSource
	LastHash   string
}

func (r *Reconfigurable) Reconfigure(ctx context.Context) {
	if dataHash, err := ConfigurePlugin(ctx, r.CoreConfig, r.Configurer, r.DataSource, r.LastHash); err != nil {
		r.Log.WithError(err).Error("Failed to reconfigure plugin")
	} else if dataHash == r.LastHash {
		r.Log.WithField(telemetry.Hash, r.LastHash).Info("Plugin not reconfigured since the config is unchanged")
	} else {
		r.Log.WithField(telemetry.OldHash, r.LastHash).WithField(telemetry.NewHash, dataHash).Info("Plugin reconfigured")
		r.LastHash = dataHash
	}
}

func configurePlugin(ctx context.Context, pluginLog logrus.FieldLogger, coreConfig CoreConfig, configurer Configurer, dataSource DataSource) (Reconfigurer, error) {
	switch {
	case configurer == nil && dataSource == nil:
		// The plugin doesn't support configuration and no data source was configured. Nothing to do.
		return nil, nil
	case configurer == nil && dataSource != nil:
		// The plugin does not support configuration but a data source was configured. This is a failure.
		return nil, errors.New("no supported configuration interface found")
	case configurer != nil && dataSource == nil:
		// The plugin supports configuration but no data source was configured. Default to an empty, fixed configuration.
		dataSource = FixedData("")
	case configurer != nil && dataSource != nil:
		// The plugin supports configuration and there was a data source.
	}

	dataHash, err := ConfigurePlugin(ctx, coreConfig, configurer, dataSource, "")
	if err != nil {
		return nil, err
	}

	if !dataSource.IsDynamic() {
		pluginLog.WithField(telemetry.Reconfigurable, false).Info("Configured plugin")
		return nil, nil
	}

	pluginLog.WithField(telemetry.Reconfigurable, true).WithField(telemetry.Hash, dataHash).Info("Configured plugin")
	return &Reconfigurable{
		Log:        pluginLog,
		CoreConfig: coreConfig,
		Configurer: configurer,
		DataSource: dataSource,
		LastHash:   dataHash,
	}, nil
}

type configurerRepo struct {
	configurer Configurer
}

func (repo *configurerRepo) Binder() any {
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

func (v1 *configurerV1) Validate(ctx context.Context, coreConfig CoreConfig, hclConfiguration string) (*configv1.ValidateResponse, error) {
	return v1.ConfigServiceClient.Validate(ctx, &configv1.ValidateRequest{
		CoreConfiguration: coreConfig.v1(),
		HclConfiguration:  hclConfiguration,
	})
}

func hashData(data string) string {
	h := sha512.New()
	_, _ = io.Copy(h, strings.NewReader(data))
	return hex.EncodeToString(h.Sum(nil)[:16])
}
