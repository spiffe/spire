package middleware

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMetricKey(t *testing.T) {
	assert.Equal(t, "one", metricKey("One"))
	assert.Equal(t, "one_two_three_four", metricKey("one,two,three,Four"))
	assert.Equal(t, "abc_def", metricKey("ABCDef"))
	assert.Equal(t, "v1", metricKey("v1"))
	assert.Equal(t, "abc_def", metricKey("AbcDEF"))
	assert.Equal(t, "one_two_three", metricKey("OneTWOThree"))
	assert.Equal(t, "one_two_three", metricKey("ONETwoTHREE"))
}
