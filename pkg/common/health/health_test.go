package health

import (
	"testing"

	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

func TestServerDisabledByDefault(t *testing.T) {
	log, _ := logtest.NewNullLogger()
	checker := NewChecker(Config{}, log)

	assert.Nil(t, checker.server)
}

func TestServerEnabled(t *testing.T) {
	log, _ := logtest.NewNullLogger()
	checker := NewChecker(Config{ListenerEnabled: true}, log)

	assert.NotNil(t, checker.server)
}
