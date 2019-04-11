package cache

import (
	"crypto/sha1"
	"encoding/base64"
	"io"
	"sort"
	"sync"

	"github.com/spiffe/spire/pkg/agent/client"
)

type JWTSVIDCache struct {
	mu    sync.Mutex
	svids map[string]*client.JWTSVID
}

func NewJWTSVIDCache() *JWTSVIDCache {
	return &JWTSVIDCache{
		svids: make(map[string]*client.JWTSVID),
	}
}

func (c *JWTSVIDCache) GetJWTSVID(spiffeID string, audience []string) (*client.JWTSVID, bool) {
	key := jwtSVIDKey(spiffeID, audience)

	c.mu.Lock()
	defer c.mu.Unlock()
	svid, ok := c.svids[key]
	return svid, ok
}

func (c *JWTSVIDCache) SetJWTSVID(spiffeID string, audience []string, svid *client.JWTSVID) {
	key := jwtSVIDKey(spiffeID, audience)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.svids[key] = svid
}

func jwtSVIDKey(spiffeID string, audience []string) string {
	h := sha1.New()

	// duplicate and sort the audience slice before sorting
	audience = append([]string(nil), audience...)
	sort.Strings(audience)

	io.WriteString(h, spiffeID)
	for _, a := range audience {
		io.WriteString(h, a)
	}

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
