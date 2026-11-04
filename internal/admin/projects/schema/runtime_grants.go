package schema

import (
	_ "embed"
	"strings"

	"github.com/jackc/pgx/v5"
)

//go:embed runtime-grants.sql
var runtimeGrants string

func RuntimeGrants(database, runtime string) string {
	db, role := pgx.Identifier{database}.Sanitize(), pgx.Identifier{runtime}.Sanitize()
	// A quoted identifier can still contain a dollar-quote delimiter. Keep the
	// atomic DO block delimiter out of both identifiers before substitution.
	tag := "$grants$"
	for strings.Contains(db, tag) || strings.Contains(role, tag) {
		tag = strings.TrimSuffix(tag, "$") + "_$"
	}
	source := strings.ReplaceAll(runtimeGrants, "$$", tag)
	return strings.NewReplacer(
		"DATABASE auth TO auth_runtime", "DATABASE "+db+" TO "+role,
		"TO auth_runtime", "TO "+role,
		"FROM auth_runtime", "FROM "+role,
	).Replace(source)
}
