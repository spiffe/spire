package v1

// This package contains API code copied from the cert-manager project:
// https://github.com/jetstack/cert-manager/tree/release-1.3/pkg/apis

// This is required for preventing go mod dependency issues when importing
// https://github.com/jetstack/cert-manager, forcing Kubernetes version bumps
// or incompatibilities. This package can be removed in future in favour of a
// stand-alone APIs repository, which you can follow the progress here
// https://github.com/jetstack/cert-manager/issues/3381.
