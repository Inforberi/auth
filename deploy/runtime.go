package deploy

import (
	_ "embed"
	"strings"

	"github.com/jackc/pgx/v5"
)

//go:embed runtime-grants.sql
var runtimeGrants string

func RuntimeGrants(database, runtime string) string {
	db, role := pgx.Identifier{database}.Sanitize(), pgx.Identifier{runtime}.Sanitize()
	return strings.NewReplacer(
		"DATABASE auth TO auth_runtime", "DATABASE "+db+" TO "+role,
		"TO auth_runtime", "TO "+role,
		"FROM auth_runtime", "FROM "+role,
	).Replace(runtimeGrants)
}
