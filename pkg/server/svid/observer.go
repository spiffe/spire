package svid

// Observer is a convenience interface for subsystems that only want to
// observer the current SVID state but don't care about other rotator
// methods.
type Observer interface {
	State() State
}

type ObserverFunc func() State

func (fn ObserverFunc) State() State {
	return fn()
}
