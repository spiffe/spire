package ssh

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/ioutil"
	"net"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	DefaultKnownHostsPath       = "/etc/ssh/ssh_known_hosts"
	AlwaysValidKnownHostsPath   = ":valid:"
	AlwaysInvalidKnownHostsPath = ":invalid:"

	PrincipalNobody = "nobody"
)

type KeyCert struct {
	*Cert

	signer ssh.Signer
}

type Cert struct {
	cert *ssh.Certificate
}

func LoadKeyCert(keyFile, certFile string) (*KeyCert, error) {
	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %v", err)
	}

	privkey, err := ssh.ParseRawPrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(privkey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %v", err)
	}

	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert file: %v", err)
	}

	cert, err := ParseCert(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cert: %v", err)
	}

	return &KeyCert{
		Cert:   cert,
		signer: signer,
	}, nil
}

func ParseCert(certBytes []byte) (*Cert, error) {
	pubkey, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	cert, ok := pubkey.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("not a valid ssh certificate")
	}

	return &Cert{cert: cert}, nil
}

// Validate checks that the principal is valid for the Cert, and that the
// known_hosts config allows the Cert to be valid for that same principal.
func (c *Cert) Validate(principal, knownHostsPath string) error {
	if len(c.cert.ValidPrincipals) == 0 {
		return errors.New("no valid principals found on cert")
	}
	found := false
	for _, p := range c.cert.ValidPrincipals {
		if p == principal {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("principal %s is not a valid principal on the cert", principal)
	}

	certChecker, err := newCertChecker(knownHostsPath)
	if err != nil {
		return fmt.Errorf("error reading known hosts files", err)
	}

	name := fmt.Sprintf("%s:22", principal)
	addr := &net.TCPAddr{IP: net.IP{127, 0, 0, 1}, Port: 22}

	if err := certChecker(name, addr, c.cert); err != nil {
		return fmt.Errorf("error validating principal: %v", err)
	}

	return nil
}

func newCertChecker(knownHostsPath string) (ssh.HostKeyCallback, error) {
	if knownHostsPath == AlwaysValidKnownHostsPath {
		return func(string, net.Addr, ssh.PublicKey) error { return nil }, nil
	} else if knownHostsPath == AlwaysInvalidKnownHostsPath {
		return func(string, net.Addr, ssh.PublicKey) error { return errors.New("always invalid certchecker") }, nil
	} else if knownHostsPath == "" {
		return knownhosts.New(DefaultKnownHostsPath)
	} else {
		return knownhosts.New(knownHostsPath)
	}
}

func (k *KeyCert) Sign(data []byte) (sig []byte, format string, _ error) {
	sshsig, err := k.signer.Sign(rand.Reader, data)
	if err != nil {
		return nil, "", err
	}
	return sshsig.Blob, sshsig.Format, nil
}

func (k *KeyCert) MarshalCert() []byte {
	return ssh.MarshalAuthorizedKey(k.Cert.cert)
}

func (c *Cert) Verify(data []byte, sig []byte, format string) error {
	return c.cert.Verify(data, &ssh.Signature{Format: format, Blob: sig})
}

func (c *Cert) FindValidPrincipal(principal string) string {
	for _, p := range c.cert.ValidPrincipals {
		if p == principal {
			return p
		}
	}
	return ""
}

func (c *Cert) ValidPrincipal() string {
	if len(c.cert.ValidPrincipals) == 0 {
		return PrincipalNobody
	}
	return c.cert.ValidPrincipals[0]
}
