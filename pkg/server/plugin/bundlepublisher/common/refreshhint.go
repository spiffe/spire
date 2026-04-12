package common

import (
	"fmt"
	"time"

	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/pluginconf"
)

func ParseRefreshHint(refreshHint string, status *pluginconf.Status) (int64, error) {
	refreshHintDuration, err := time.ParseDuration(refreshHint)
	if err != nil {
		return 0, fmt.Errorf("could not parse refresh hint %q: %w", refreshHint, err)
	}
	if refreshHintDuration >= 24*time.Hour {
		status.ReportInfo("Bundle endpoint refresh hint set to a high value. To cover " +
			"the case of unscheduled trust bundle updates, it's recommended to " +
			"have a smaller value, e.g. 5m")
	}

	if refreshHintDuration < bundleutil.MinimumRefreshHint {
		status.ReportInfo("Bundle endpoint refresh hint set too low. SPIRE will not " +
			"refresh more often than 1 minute")
	}
	return int64(refreshHintDuration.Seconds()), nil
}
