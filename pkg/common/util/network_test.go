package util

import (
	"net"
	"testing"
)

func TestUpdateAddressIPV4(t *testing.T) {
	hostname := "localhost"
	initialIP := "0.0.0.0"
	expectedAddr := "127.0.0.1:8081"

	addr := net.TCPAddr{IP: net.ParseIP(initialIP), Port: 8081}
	newAddr, err := UpdateAddress(&addr, hostname)

	if err != nil {
		t.Fatal("Fail to update address", err)
	}

	if newAddr.String() != expectedAddr {
		t.Fatal("Address mismatch")
		t.Log("ACTUAL:", newAddr.String())
		t.Log("EXPECTED:", expectedAddr)
	}

}

func TestUpdateAddressIPV6(t *testing.T) {
	hostnames, err := net.LookupHost("::1")
	if err != nil {
		t.Fatal("Fail to retrieve localhost name")
	}

	hostname := hostnames[0] // abstract platform-specific names for "ip6-localhost"
	initialIP := "::0"
	expectedAddr := "[::1]:8081"

	addr := net.TCPAddr{IP: net.ParseIP(initialIP), Port: 8081}
	newAddr, err := UpdateAddress(&addr, hostname)

	if err != nil {
		t.Fatal("Fail to update address", err)
	}

	if newAddr.String() != expectedAddr {
		t.Log("ACTUAL:", newAddr.String())
		t.Log("EXPECTED:", expectedAddr)
		t.Fatal("Address mismatch")
	}
}
