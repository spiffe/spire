package main

import "github.com/zeebo/errs"

var (
	NotFound = errs.Class("not found")
)

const (
	NamespaceName = "spire"
)
