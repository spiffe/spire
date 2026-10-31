package sqlstorev2

import (
	"math"
	"testing"

	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"github.com/stretchr/testify/require"
)

func TestParsePaginationToken(t *testing.T) {
	for _, tt := range []struct {
		name        string
		token       string
		dbType      string
		expectedID  uint64
		expectedErr string
	}{
		{
			name:       "sqlite token within range",
			token:      "5000000000",
			dbType:     sqlcommon.SQLite,
			expectedID: 5000000000,
		},
		{
			name:       "postgres token within range",
			token:      "42",
			dbType:     sqlcommon.PostgreSQL,
			expectedID: 42,
		},
		{
			name:       "postgres token beyond 32 bits is clamped",
			token:      "5000000000",
			dbType:     sqlcommon.PostgreSQL,
			expectedID: math.MaxInt32,
		},
		{
			name:       "mysql token beyond 32 bits is clamped",
			token:      "5000000000",
			dbType:     sqlcommon.MySQL,
			expectedID: math.MaxUint32,
		},
		{
			name:        "invalid token",
			token:       "not a number",
			dbType:      sqlcommon.SQLite,
			expectedErr: "rpc error: code = InvalidArgument desc = could not parse token 'not a number'",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			id, err := parsePaginationToken(tt.token, tt.dbType)
			if tt.expectedErr != "" {
				require.EqualError(t, err, tt.expectedErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectedID, id)
		})
	}
}
