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
	mu    sync.Mutex
	state *state
}

type stream struct {
	property *property
	state    *state
}

type state struct {
	value any
	next  *state
	done  chan struct{}
}

// NewProperty creates a property with the provided initial value.
func NewProperty(value any) Property {
	return &property{
		state: newState(value),
	}
}

func (p *property) Value() any {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.state.value
}

func (p *property) Update(value any) {
	p.mu.Lock()
	defer p.mu.Unlock()

	next := newState(value)
	p.state.next = next
	close(p.state.done)
	p.state = next
}

func (p *property) Observe() Stream {
	p.mu.Lock()
	defer p.mu.Unlock()

	return &stream{
		property: p,
		state:    p.state,
	}
}

func (s *stream) Value() any {
	s.property.mu.Lock()
	defer s.property.mu.Unlock()

	return s.state.value
}

func (s *stream) Changes() chan struct{} {
	s.property.mu.Lock()
	defer s.property.mu.Unlock()

	return s.state.done
}

func (s *stream) Next() any {
	s.property.mu.Lock()
	defer s.property.mu.Unlock()

	if s.state.next != nil {
		s.state = s.state.next
	}
	return s.state.value
}

func (s *stream) WaitNext() any {
	<-s.Changes()
	return s.Next()
}

func (s *stream) HasNext() bool {
	s.property.mu.Lock()
	defer s.property.mu.Unlock()

	return s.state.next != nil
}

func (s *stream) Clone() Stream {
	s.property.mu.Lock()
	defer s.property.mu.Unlock()

	return &stream{
		property: s.property,
		state:    s.state,
	}
}

func newState(value any) *state {
	return &state{
		value: value,
		done:  make(chan struct{}),
	}
}
