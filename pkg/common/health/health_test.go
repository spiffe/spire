package health

import (
	"testing"

	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerDisabledByDefault(t *testing.T) {
	log, _ := logtest.NewNullLogger()
	checker, ok := NewChecker(Config{}, log).(*checker)
	require.True(t, ok)

	assert.Nil(t, checker.server)
}

func TestServerEnabled(t *testing.T) {
	log, _ := logtest.NewNullLogger()
	checker, ok := NewChecker(Config{ListenerEnabled: true}, log).(*checker)
	require.True(t, ok)

	assert.NotNil(t, checker.server)
}
