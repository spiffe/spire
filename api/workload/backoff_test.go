package workload

import (
	"testing"
	"time"
)

func TestBackoff(t *testing.T) {
	timeout := 100 * time.Millisecond
	b := newBackoff(timeout, false)

	shutdown := make(chan struct{})
	b.current = 1 * time.Millisecond
	goAgain := make(chan bool)
	go func() { goAgain <- b.goAgain(shutdown) }()
	select {
	case <-time.NewTicker(2 * time.Millisecond).C:
		t.Error("backoff timer exceeded")
	case again := <-goAgain:
		if again != true {
			t.Error("expected goAgain when within timeout")
		}
	}

	go func() { goAgain <- b.goAgain(shutdown) }()
	select {
	case <-time.NewTicker(3 * time.Millisecond).C:
		t.Error("backoff timer exceeded")
	case again := <-goAgain:
		if again != true {
			t.Error("expected goAgain when within timeout")
		}
	}

	go func() { goAgain <- b.goAgain(shutdown) }()
	select {
	case <-time.NewTicker(5 * time.Millisecond).C:
		t.Error("backoff timer exceeded")
	case again := <-goAgain:
		if again != true {
			t.Error("expected goAgain when within timeout")
		}
	}

	go func() { goAgain <- b.goAgain(shutdown) }()
	close(shutdown)
	select {
	case <-time.NewTicker(5 * time.Millisecond).C:
		t.Error("backoff did not shutdown early")
	case again := <-goAgain:
		if again != false {
			t.Error("goAgain true after shutdown")
		}
	}

	timeout = 3 * time.Millisecond
	b = newBackoff(timeout, false)
	shutdown = make(chan struct{})
	b.current = 1 * time.Millisecond
	b.goAgain(shutdown)
	b.goAgain(shutdown)
	again := b.goAgain(shutdown)
	if again != false {
		t.Error("goAgain not false after exceeding timeout")
	}

}
