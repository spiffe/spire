package svid

import (
	"testing"
)

func TestNewRotator(t *testing.T) {
	r, _ := NewRotator(&RotatorConfig{})
	if r.c.Interval == 0 {
		t.Error("svid rotator interval should not be 0")
	}
}
