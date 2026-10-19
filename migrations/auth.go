package migrations

import _ "embed"

//go:embed 000001_init.up.sql
var initialAuth string

const AuthVersion = 1

func InitialAuth() string { return initialAuth }
