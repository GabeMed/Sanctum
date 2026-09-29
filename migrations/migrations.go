// Package migrations embeds the SQL schema files so the server binary can
// apply them without shipping the directory.
package migrations

import "embed"

// FS holds every *.sql file in this directory.
//
//go:embed *.sql
var FS embed.FS
