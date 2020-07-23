package vault

import (
	"fmt"

	"github.com/hashicorp/go-hclog"
	vapi "github.com/hashicorp/vault/api"
)

type Renew struct {
	Logger  hclog.Logger
	renewer *vapi.Renewer
}

func NewRenew(client *vapi.Client, secret *vapi.Secret, logger hclog.Logger) (*Renew, error) {
	renewer, err := client.NewRenewer(&vapi.RenewerInput{
		Secret: secret,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Renewer: %v", err)
	}
	return &Renew{
		Logger:  logger,
		renewer: renewer,
	}, nil
}

func (r *Renew) Run() {
	go r.renewer.Renew()
	defer r.renewer.Stop()

	for {
		select {
		case err := <-r.renewer.DoneCh():
			if err != nil {
				r.Logger.Warn("Failed to renew auth token", "err", err.Error())
			}
		case renewal := <-r.renewer.RenewCh():
			r.Logger.Debug("Successfully renew auth token", "request_id", renewal.Secret.RequestID)
		}
	}
}
