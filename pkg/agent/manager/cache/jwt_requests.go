package cache

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/common/telemetry/agent"
	"github.com/spiffe/spire/proto/spire/common"
)

// JWTRegistration separates cached tokens when a registration changes.
type JWTRegistration struct {
	EntryID        string
	RevisionNumber int64
	SPIFFEID       string
}

func RegistrationForJWT(entry *common.RegistrationEntry) JWTRegistration {
	return JWTRegistration{EntryID: entry.EntryId, RevisionNumber: entry.RevisionNumber, SPIFFEID: entry.SpiffeId}
}

// JWTSVIDRequestKey identifies signing work and cached results for a registration.
func JWTSVIDRequestKey(entry *common.RegistrationEntry, audience []string) string {
	audience = slices.Clone(audience)
	slices.Sort(audience)
	audience = slices.Compact(audience)
	parts := []string{entry.EntryId, strconv.FormatInt(entry.RevisionNumber, 10), entry.SpiffeId}
	parts = append(parts, audience...)
	var key strings.Builder
	for _, part := range parts {
		key.WriteString(strconv.Itoa(len(part)))
		key.WriteByte(':')
		key.WriteString(part)
	}
	return key.String()
}

func (c *JWTSVIDCache) GetJWTSVIDForRequest(key string) (*client.JWTSVID, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	element := c.svids[key]
	if element == nil {
		return nil, false
	}
	c.lruList.MoveToFront(element)
	svid := *element.Value.(jwtSvidElement).svid
	return &svid, true
}

func (c *JWTSVIDCache) SetJWTSVIDForRequest(key string, registration JWTRegistration, svid *client.JWTSVID) error {
	defer func() { agent.SetJWTSVIDCacheSize(c.metrics, c.CountJWTSVIDs()) }()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.validateJWTSVID(svid); err != nil {
		return err
	}
	svidCopy := *svid
	value := jwtSvidElement{key: key, svid: &svidCopy, registration: &registration}
	if element := c.svids[key]; element != nil {
		element.Value = value
		c.lruList.MoveToFront(element)
		return nil
	}
	if len(c.svids) >= c.svidCacheMaxSize {
		element := c.lruList.Back()
		delete(c.svids, element.Value.(jwtSvidElement).key)
		c.lruList.Remove(element)
	}
	c.svids[key] = c.lruList.PushFront(value)
	return nil
}

func (c *JWTSVIDCache) RetainJWTRegistrations(authorized map[JWTRegistration]struct{}) {
	defer func() { agent.SetJWTSVIDCacheSize(c.metrics, c.CountJWTSVIDs()) }()
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, element := range c.svids {
		registration := element.Value.(jwtSvidElement).registration
		if registration == nil {
			continue
		}
		if _, ok := authorized[*registration]; !ok {
			delete(c.svids, key)
			c.lruList.Remove(element)
		}
	}
}

func (c *JWTSVIDCache) validateJWTSVID(svid *client.JWTSVID) error {
	if svid == nil {
		return errors.New("missing JWT-SVID")
	}
	kid, err := getKeyIDFromSVIDToken(svid.Token)
	if err != nil {
		return err
	}
	if _, tainted := c.taintedAuthorities[kid]; tainted {
		return fmt.Errorf("JWT-SVID was issued by tainted authority %q", kid)
	}
	return nil
}
