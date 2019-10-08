package telemetry

import (
	"github.com/spiffe/spire/pkg/common/version"
)

func EmitVersion(m Metrics) {
	m.SetGaugeWithLabels([]string{"version"}, 1, []Label{
		{Name: "version", Value: version.Version()},
	})
}
