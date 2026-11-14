package auth

import _ "embed"

//go:embed 000001_init.up.sql
var initialAuth string

//go:embed 000002_settings_source.up.sql
var settingsSource string

const AuthVersion = 2

func InitialAuth() string { return initialAuth + "\n" + settingsSource }
