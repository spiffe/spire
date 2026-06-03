# Go Text Template Engine

## About

In various plugins, the go based text/template engine is used. More information about this language can be found in the [text/template documentation](https://pkg.go.dev/text/template).

## Functions

In addition to the built in functions as described in the [text/template functions documentation](https://pkg.go.dev/text/template#hdr-Functions), we also include a set of functions from the SPRIG library.

The list of SPRIG functions is available in the [agent path template function list](https://github.com/spiffe/spire/blob/main/pkg/common/agentpathtemplate/template.go#L11).

The functions behavior can be found in the [SPRIG documentation](https://masterminds.github.io/sprig/).
