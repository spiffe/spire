package atomic

import "sync"

// Bool is an atomic bool.
type Bool struct {
	mu    sync.RWMutex
	value bool
}

// NewBool returns a new atomic bool.
func NewBool(value bool) *Bool {
	return &Bool{value: value}
}

func (b *Bool) Set(value bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.value = value
}

func (b *Bool) Get() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.value
}
