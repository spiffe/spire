package x509certificate

import (
	"crypto/x509"

	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/proto/spire/common"
)

func RequireFromCommonProto(pb *common.Certificate) *X509Authority {
	out, err := FromCommonProto(pb)
	panicOnError(err)
	return out
}

func RequireFromCommonProtos(pbs []*common.Certificate) []*X509Authority {
	out, err := FromCommonProtos(pbs)
	panicOnError(err)
	return out
}

func RequireToCommonProto(x509Certificate *X509Authority) *common.Certificate {
	out, err := ToCommonProto(x509Certificate)
	panicOnError(err)
	return out
}

func RequireToCommonProtos(x509Certificates []*X509Authority) []*common.Certificate {
	out, err := ToCommonProtos(x509Certificates)
	panicOnError(err)
	return out
}

func RequireToCommonFromPluginProtos(pbs []*plugintypes.X509Certificate) []*common.Certificate {
	out, err := ToCommonFromPluginProtos(pbs)
	panicOnError(err)
	return out
}

func RequireFromPluginProto(pb *plugintypes.X509Certificate) *X509Authority {
	out, err := FromPluginProto(pb)
	panicOnError(err)
	return out
}

func RequireFromPluginProtos(pbs []*plugintypes.X509Certificate) []*X509Authority {
	out, err := FromPluginProtos(pbs)
	panicOnError(err)
	return out
}

func RequireToPluginProto(x509Certificate *X509Authority) *plugintypes.X509Certificate {
	out, err := ToPluginProto(x509Certificate)
	panicOnError(err)
	return out
}

func RequireToPluginProtos(x509Certificates []*X509Authority) []*plugintypes.X509Certificate {
	out, err := ToPluginProtos(x509Certificates)
	panicOnError(err)
	return out
}

func RequireToPluginFromCommonProtos(pbs []*common.Certificate) []*plugintypes.X509Certificate {
	out, err := ToPluginFromCommonProtos(pbs)
	panicOnError(err)
	return out
}

func RequireToPluginFromCertificates(x509Certificates []*x509.Certificate) []*plugintypes.X509Certificate {
	pbs, err := ToPluginFromCertificates(x509Certificates)
	panicOnError(err)
	return pbs
}

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}
