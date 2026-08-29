package vault

import (
	"github.com/hashicorp/go-hclog"
	vapi "github.com/hashicorp/vault/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	defaultRenewBehavior = vapi.RenewBehaviorIgnoreErrors
)

type Renew struct {
	logger  hclog.Logger
	watcher *vapi.LifetimeWatcher
}

func NewRenew(client *vapi.Client, secret *vapi.Secret, logger hclog.Logger) (*Renew, error) {
	watcher, err := client.NewLifetimeWatcher(&vapi.LifetimeWatcherInput{
		Secret:        secret,
		RenewBehavior: defaultRenewBehavior,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to initialize Renewer: %v", err)
	}
	return &Renew{
		logger:  logger,
		watcher: watcher,
	}, nil
}

func (r *Renew) Run() {
	go r.watcher.Start()
	defer r.watcher.Stop()

	for {
		select {
		case err := <-r.watcher.DoneCh():
			if err != nil {
				r.logger.Error("Failed to renew auth token", "err", err)
				return
			}
			r.logger.Error("Failed to renew auth token. Retries may have exceeded the lease time threshold")
			return
		case renewal := <-r.watcher.RenewCh():
			r.logger.Debug("Successfully renew auth token", "request_id", renewal.Secret.RequestID, "lease_duration", renewal.Secret.Auth.LeaseDuration)
		}
	}
}
