package fakehealthchecker

import (
	"fmt"

	"github.com/spiffe/spire/pkg/common/health"
)

type Checker struct {
	checkables map[string]health.Checkable
}

var _ health.Checker = (*Checker)(nil)

func New() *Checker {
	return &Checker{
		checkables: make(map[string]health.Checkable),
	}
}

func (c *Checker) AddCheck(name string, checkable health.Checkable) error {
	if _, ok := c.checkables[name]; ok {
		return fmt.Errorf("check %q has already been added", name)
	}
	c.checkables[name] = checkable
	return nil
}

func (c *Checker) LiveState() (bool, interface{}) {
	live := true
	details := make(map[string]interface{})

	for name, checkable := range c.checkables {
		if !checkable.CheckHealth().Live {
			live = false
		}

		details[name] = checkable.CheckHealth().LiveDetails
	}
	return live, details
}

func (c *Checker) ReadyState() (bool, interface{}) {
	ready := true
	details := make(map[string]interface{})

	for name, checkable := range c.checkables {
		if !checkable.CheckHealth().Ready {
			ready = false
		}

		details[name] = checkable.CheckHealth().ReadyDetails
	}
	return ready, details
}

func (c *Checker) RunChecks() map[string]health.State {
	results := make(map[string]health.State)
	for name, checkable := range c.checkables {
		results[name] = checkable.CheckHealth()
	}
	return results
}
