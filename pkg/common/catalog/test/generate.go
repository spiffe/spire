//go:generate $GOPATH/bin/spire-plugingen -shared -mode plugin . TestPlugin
//go:generate $GOPATH/bin/spire-plugingen -shared -mode service . TestService
//go:generate $GOPATH/bin/spire-plugingen -shared -mode hostservice . TestHostService
package test
