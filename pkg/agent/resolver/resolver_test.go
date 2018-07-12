package resolver

import (
	"github.com/sirupsen/logrus"

	"net"
	"testing"
)

func TestLookupIPV4(t *testing.T) {
	hostname := "localhost"
	initialIP := "0.0.0.0"
	expectedAddr := "127.0.0.1:8081"
	addr := net.TCPAddr{IP: net.ParseIP(initialIP), Port: 8081}

	resolver := New(hostname, &addr, logrus.New())
	newAddr := resolver.Lookup()

	if newAddr.String() != expectedAddr {
		t.Log("ACTUAL:", newAddr.String())
		t.Log("EXPECTED:", expectedAddr)
		t.Fatal("Address mismatch")
	}
}

func TestLookupIPV4WhenHostnameIsAnIP(t *testing.T) {
	hostname := "127.0.0.1"
	initialIP := "0.0.0.0"
	expectedAddr := "127.0.0.1:8081"
	addr := net.TCPAddr{IP: net.ParseIP(initialIP), Port: 8081}

	resolver := New(hostname, &addr, logrus.New())
	newAddr := resolver.Lookup()

	if newAddr.String() != expectedAddr {
		t.Log("ACTUAL:", newAddr.String())
		t.Log("EXPECTED:", expectedAddr)
		t.Fatal("Address mismatch")
	}
}

func TestLookupIPV4WhenInitialIPIsEmpty(t *testing.T) {
	hostname := "localhost"
	initialIP := ""
	expectedAddr := "127.0.0.1:8081"
	addr := net.TCPAddr{IP: net.ParseIP(initialIP), Port: 8081}

	resolver := New(hostname, &addr, logrus.New())
	newAddr := resolver.Lookup()

	if newAddr.String() != expectedAddr {
		t.Log("ACTUAL:", newAddr.String())
		t.Log("EXPECTED:", expectedAddr)
		t.Fatal("Address mismatch")
	}
}

func TestLookupIPV6(t *testing.T) {
	hostnames, err := net.LookupHost("::1")
	if err != nil {
		t.Fatal("Fail to retrieve localhost name")
	}

	hostname := hostnames[0] // abstract platform-specific names for "ip6-localhost"
	initialIP := "::0"
	expectedAddr := "[::1]:8081"
	addr := net.TCPAddr{IP: net.ParseIP(initialIP), Port: 8081}

	resolver := New(hostname, &addr, logrus.New())
	newAddr := resolver.Lookup()

	if newAddr.String() != expectedAddr {
		t.Log("ACTUAL:", newAddr.String())
		t.Log("EXPECTED:", expectedAddr)
		t.Fatal("Address mismatch")
	}
}

func TestLookupIPV6WhenHostnameIsAnIP(t *testing.T) {
	hostname := "::1"
	initialIP := "::0"
	expectedAddr := "[::1]:8081"
	addr := net.TCPAddr{IP: net.ParseIP(initialIP), Port: 8081}

	resolver := New(hostname, &addr, logrus.New())
	newAddr := resolver.Lookup()

	if newAddr.String() != expectedAddr {
		t.Log("ACTUAL:", newAddr.String())
		t.Log("EXPECTED:", expectedAddr)
		t.Fatal("Address mismatch")
	}
}

func TestLookupIPV6WhenInitialIPIsEmpty(t *testing.T) {
	hostnames, err := net.LookupHost("::1")
	if err != nil {
		t.Fatal("Fail to retrieve localhost name")
	}

	hostname := hostnames[0] // abstract platform-specific names for "ip6-localhost"
	initialIP := ""
	expectedAddr := "[::1]:8081"
	addr := net.TCPAddr{IP: net.ParseIP(initialIP), Port: 8081}

	resolver := New(hostname, &addr, logrus.New())
	newAddr := resolver.Lookup()

	if newAddr.String() != expectedAddr {
		t.Log("ACTUAL:", newAddr.String())
		t.Log("EXPECTED:", expectedAddr)
		t.Fatal("Address mismatch")
	}
}
