// This package contains the interfaces and functions used by both the catalog
// and generated plugin/service/hostservice code. It needs to live in a
// separate package so that we don't get cyclic dependencies using generated
// code for unit tests in the catalog package. Using the "internal" package
// prevents other packages from taking a dependency on the contents, instead
// having to use the aliases in the catalog package.
package internal
