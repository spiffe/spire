package x509certificate

import (
	"crypto/x509"

	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/proto/spire/common"
)

func RequireFromCommonProto(pb *common.Certificate) *x509.Certificate {
	out, err := FromCommonProto(pb)
	panicOnError(err)
	return out
}

func RequireFromCommonProtos(pbs []*common.Certificate) []*x509.Certificate {
	out, err := FromCommonProtos(pbs)
	panicOnError(err)
	return out
}

func RequireToCommonProto(x509Certificate *x509.Certificate) *common.Certificate {
	out, err := ToCommonProto(x509Certificate)
	panicOnError(err)
	return out
}

func RequireToCommonProtos(x509Certificates []*x509.Certificate) []*common.Certificate {
	out, err := ToCommonProtos(x509Certificates)
	panicOnError(err)
	return out
}

func RequireToCommonFromPluginProtos(pbs []*plugintypes.X509Certificate) []*common.Certificate {
	out, err := ToCommonFromPluginProtos(pbs)
	panicOnError(err)
	return out
}

func RequireFromPluginProto(pb *plugintypes.X509Certificate) *x509.Certificate {
	out, err := FromPluginProto(pb)
	panicOnError(err)
	return out
}

func RequireFromPluginProtos(pbs []*plugintypes.X509Certificate) []*x509.Certificate {
	out, err := FromPluginProtos(pbs)
	panicOnError(err)
	return out
}

func RequireToPluginProto(x509Certificate *x509.Certificate) *plugintypes.X509Certificate {
	out, err := ToPluginProto(x509Certificate)
	panicOnError(err)
	return out
}

func RequireToPluginProtos(x509Certificates []*x509.Certificate) []*plugintypes.X509Certificate {
	out, err := ToPluginProtos(x509Certificates)
	panicOnError(err)
	return out
}

func RequireToPluginFromCommonProtos(pbs []*common.Certificate) []*plugintypes.X509Certificate {
	out, err := ToPluginFromCommonProtos(pbs)
	panicOnError(err)
	return out
}

func RequireRawFromCommonProto(pb *common.Certificate) []byte {
	out, err := RawFromCommonProto(pb)
	panicOnError(err)
	return out
}

func RequireRawFromCommonProtos(pbs []*common.Certificate) [][]byte {
	out, err := RawFromCommonProtos(pbs)
	panicOnError(err)
	return out
}

func RequireRawToCommonProto(rawX509Certificate []byte) *common.Certificate {
	out, err := RawToCommonProto(rawX509Certificate)
	panicOnError(err)
	return out
}

func RequireRawToCommonProtos(rawX509Certificates [][]byte) []*common.Certificate {
	out, err := RawToCommonProtos(rawX509Certificates)
	panicOnError(err)
	return out
}

func RequireRawFromPluginProto(pb *plugintypes.X509Certificate) []byte {
	out, err := RawFromPluginProto(pb)
	panicOnError(err)
	return out
}

func RequireRawFromPluginProtos(pbs []*plugintypes.X509Certificate) [][]byte {
	out, err := RawFromPluginProtos(pbs)
	panicOnError(err)
	return out
}

func RequireRawToPluginProto(rawX509Certificate []byte) *plugintypes.X509Certificate {
	out, err := RawToPluginProto(rawX509Certificate)
	panicOnError(err)
	return out
}

func RequireRawToPluginProtos(rawX509Certificates [][]byte) []*plugintypes.X509Certificate {
	out, err := RawToPluginProtos(rawX509Certificates)
	panicOnError(err)
	return out
}

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}
