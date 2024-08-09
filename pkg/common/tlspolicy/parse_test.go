package tlspolicy

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/log"
	"github.com/stretchr/testify/require"
)

func TestParsePQKEMMode(t *testing.T) {
	require := require.New(t)
	logger, err := log.NewLogger(log.WithLevel("ERROR"))
	require.NoError(err)

	for _, s := range []struct {
		Name        string
		Value       PQKEMMode
		ExpectError bool
	}{
		{"", PQKEMModeDefault, false},
		{"default", PQKEMModeDefault, false},
		{"attempt", PQKEMModeAttempt, false},
		{"require", PQKEMModeRequire, !SupportsPQKEM},
		{"foo", PQKEMModeDefault, true},
	} {
		r, err := ParsePQKEMMode(log.NewHCLogAdapter(logger, "tlspolicy"), s.Name)
		if s.ExpectError {
			require.Error(err)
		} else {
			require.NoError(err)
			if SupportsPQKEM {
				require.Equal(r, s.Value)
			} else {
				require.Equal(r, PQKEMModeDefault)
			}
		}
	}
}
