package resolver

import (
	"github.com/sirupsen/logrus"

	"net"
)

type Resolver interface {
	Lookup() net.Addr
}

type resolver struct {
	log      logrus.StdLogger
	hostname string
	address  net.Addr
}

// New creates a new resolver type.
func New(hostname string, address net.Addr, log logrus.StdLogger) *resolver {
	return &resolver{
		hostname: hostname,
		address:  address,
		log:      log,
	}
}

// Lookup an address based on hostname.
// In case of error, the last looked up address is returned and an error is logged.
func (r *resolver) Lookup() net.Addr {
	_, port, err := net.SplitHostPort(r.address.String())
	if err != nil {
		r.log.Printf("Fail to look up. Cannot split host and port. Returning last address found. %v", err)
		return r.address
	}

	ips, err := net.LookupIP(r.hostname)
	if err != nil {
		r.log.Printf("Fail to look up. Cannot resolve hostname. Returning last address found. %v", err)
		return r.address
	}

	strAddr := net.JoinHostPort(ips[0].String(), port)
	newAddr, err := net.ResolveTCPAddr(r.address.Network(), strAddr)
	if err != nil {
		r.log.Printf("Fail to look up. Cannot create new address. Returning last address found. %v", err)
		return r.address
	}
	r.address = newAddr
	return r.address
}
