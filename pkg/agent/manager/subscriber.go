package manager

import (
	"github.com/satori/go.uuid"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
)

type subscriber struct {
	c    chan []cache.Entry
	sel  cache.Selectors
	done chan struct{}
}

// subscribers is a map keyed by the Cache key, with a vaule mapped by Subscriber ID.
type subscribers map[string]map[string]subscriber

func (*s subscribers) Add(sub subscriber) error {
	

	sID, err := uuid.NewV4()
	if err != nil {
		return err
	}

	// s[sub.sel.Key] = append(s[sub.sek.Key], sub)
}

// func (*s subscribers) Remove(key string, id string) {
// 	delete(s[key])
// }