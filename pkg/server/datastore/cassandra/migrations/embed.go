package migrations

import (
	"embed"
)

//go:embed *.cql
var Migrations embed.FS
