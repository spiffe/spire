package observer

import "sync"

// Property stores a value and allows observers to subscribe to updates.
type Property interface {
	Value() any
	Update(any)
	Observe() Stream
}

// Stream observes updates to a Property.
type Stream interface {
	Value() any
	Changes() chan struct{}
	Next() any
	WaitNext() any
	HasNext() bool
	Clone() Stream
}

type property struct {
	mu      sync.Mutex
	value   any
	updates []any
	streams map[*stream]struct{}
}

type stream struct {
	property *property
	value    any
	next     int

	changes       chan struct{}
	changesClosed bool
}

// NewProperty creates a property with the provided initial value.
func NewProperty(value any) Property {
	return &property{
		value:   value,
		streams: make(map[*stream]struct{}),
	}
}

func (p *property) Value() any {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.value
}

func (p *property) Update(value any) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.value = value
	p.updates = append(p.updates, value)

	for s := range p.streams {
		if s.hasNextLocked() {
			s.closeChangesLocked()
		}
	}
}

func (p *property) Observe() Stream {
	p.mu.Lock()
	defer p.mu.Unlock()

	s := &stream{
		property: p,
		value:    p.value,
		next:     len(p.updates),
		changes:  make(chan struct{}),
	}
	p.streams[s] = struct{}{}
	return s
}

func (s *stream) Value() any {
	s.property.mu.Lock()
	defer s.property.mu.Unlock()

	return s.value
}

func (s *stream) Changes() chan struct{} {
	s.property.mu.Lock()
	defer s.property.mu.Unlock()

	if s.hasNextLocked() {
		s.closeChangesLocked()
	}
	return s.changes
}

func (s *stream) Next() any {
	s.property.mu.Lock()
	defer s.property.mu.Unlock()

	if !s.hasNextLocked() {
		return s.value
	}

	s.value = s.property.updates[s.next]
	s.next++
	s.changes = make(chan struct{})
	s.changesClosed = false
	if s.hasNextLocked() {
		s.closeChangesLocked()
	}
	return s.value
}

func (s *stream) WaitNext() any {
	<-s.Changes()
	return s.Next()
}

func (s *stream) HasNext() bool {
	s.property.mu.Lock()
	defer s.property.mu.Unlock()

	return s.hasNextLocked()
}

func (s *stream) Clone() Stream {
	s.property.mu.Lock()
	defer s.property.mu.Unlock()

	clone := &stream{
		property: s.property,
		value:    s.value,
		next:     s.next,
		changes:  make(chan struct{}),
	}
	if clone.hasNextLocked() {
		clone.closeChangesLocked()
	}
	s.property.streams[clone] = struct{}{}
	return clone
}

func (s *stream) hasNextLocked() bool {
	return s.next < len(s.property.updates)
}

func (s *stream) closeChangesLocked() {
	if s.changesClosed {
		return
	}
	close(s.changes)
	s.changesClosed = true
}
