package coreconfig

import (
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
)

type CoreConfig struct {
	TrustDomain spiffeid.TrustDomain
}

func (c CoreConfig) V1() *configv1.CoreConfiguration {
	return &configv1.CoreConfiguration{
		TrustDomain: c.TrustDomain.Name(),
	}
}
