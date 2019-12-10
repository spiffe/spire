//go:generate $GOPATH/bin/spire-plugingen -shared -mode plugin . Plugin
//go:generate $GOPATH/bin/spire-plugingen -shared -mode service . Service
//go:generate $GOPATH/bin/spire-plugingen -shared -mode hostservice . HostService
package test
