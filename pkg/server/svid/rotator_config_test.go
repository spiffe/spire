package svid

import (
	"testing"
)

func TestNewRotator(t *testing.T) {
	r := NewRotator(&RotatorConfig{})
	if r.Interval() != DefaultRotatorInterval {
		t.Error("svid rotator interval should be set to its default value")
	}
}
