package store

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/manager/pipe"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_store "github.com/spiffe/spire/pkg/common/telemetry/agent/store"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/common/x509util"
)

type Service interface {
	// Run start the store service. It will block until the context is cancelled.
	Run(ctx context.Context) error
}

type Config struct {
	Log       logrus.FieldLogger
	PipeOut   pipe.Out
	Metrics   telemetry.Metrics
	SVIDStore svidstore.SVIDStore
}

func New(c Config) Service {
	return &service{
		c: &c,
	}
}

type service struct {
	c *Config

	hooks struct {
		// test hook used to verify put is done
		stored chan struct{}
	}
}

func (p *service) Run(ctx context.Context) error {
	err := util.RunTasks(ctx,
		p.run,
	)

	switch {
	case err == nil || err == context.Canceled:
		p.c.Log.Info("Service stopped")
		return nil
	default:
		p.c.Log.WithError(err).Error("Service crashed")
		return err
	}
}

func (p *service) run(ctx context.Context) error {
	for {
		select {
		case update := <-p.c.PipeOut.GetUpdate():
			p.putSVID(ctx, update)
			// It is only used for unit tests
			p.triggerStoredHook()
		case <-ctx.Done():
			return nil
		}
	}
}

func (p *service) putSVID(ctx context.Context, update *pipe.SVIDUpdate) {
	counter := telemetry_store.StartPutSVIDCall(p.c.Metrics)
	defer counter.Done(nil)

	log := p.c.Log.WithFields(logrus.Fields{
		telemetry.Entry: update.Entry.EntryId,
	})

	req, err := parseUpdate(update)
	if err != nil {
		log.WithError(err).Error("Failed to create request from update")
		return
	}

	if _, err := p.c.SVIDStore.PutX509SVID(ctx, req); err != nil {
		log.WithError(err).Errorf("Failed to store X509-SVID")
		return
	}

	log.Debug("X509-SVID stored successfully")
}

// triggerStoredHook is only used for unit tests to verify put finished
func (p *service) triggerStoredHook() {
	if p.hooks.stored != nil {
		p.hooks.stored <- struct{}{}
	}
}

// parseUpdate parses an SVID Update into a *svidstore.PutX509SVIDRequest request
func parseUpdate(update *pipe.SVIDUpdate) (*svidstore.PutX509SVIDRequest, error) {
	federatedBundles := make(map[string][]byte)
	for id, fBundle := range update.FederatedBundles {
		federatedBundles[id] = marshalBundle(fBundle)
	}

	keyData, err := x509.MarshalPKCS8PrivateKey(update.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key for entry ID %q: %v", update.Entry.EntryId, err)
	}

	return &svidstore.PutX509SVIDRequest{
		Selectors: update.Entry.Selectors,
		Svid: &svidstore.X509SVID{
			SpiffeId:   update.Entry.SpiffeId,
			Bundle:     marshalBundle(update.Bundle),
			CertChain:  x509util.DERFromCertificates(update.SVID),
			PrivateKey: keyData,
			ExpiresAt:  update.Entry.EntryExpiry,
		},
		FederatedBundles: federatedBundles,
	}, nil
}

func marshalBundle(b *bundleutil.Bundle) []byte {
	var bundle []byte
	for _, b := range b.RootCAs() {
		bundle = append(bundle, b.Raw...)
	}

	return bundle
}
