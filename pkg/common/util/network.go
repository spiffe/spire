package util

import "net"

// UpdateAddress does a lookup of the IP based on hostname and returns an updated address.
// In case of error, the original address is returned
func UpdateAddress(addr net.Addr, hostname string) (net.Addr, error) {

	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr, err
	}

	ips, err := net.LookupIP(hostname)
	if err != nil {
		return addr, err
	}

	strAddr := net.JoinHostPort(ips[0].String(), port)
	newAddr, err := net.ResolveTCPAddr(addr.Network(), strAddr)

	if err != nil {
		return addr, err
	}

	return newAddr, nil
}
