package telemetry

import (
	"github.com/spiffe/spire/pkg/common/version"
)

func EmitVersion(m Metrics) {
	m.SetGaugeWithLabels([]string{"started"}, 1, []Label{
		{Name: "version", Value: version.Version()},
	})
}
