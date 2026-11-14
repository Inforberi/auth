package auth

import _ "embed"

//go:embed 000001_init.up.sql
var initialAuth string

//go:embed 000002_settings_source.up.sql
var settingsSource string

//go:embed 000003_email_otp_policy.up.sql
var emailOTPPolicy string

//go:embed 000004_browser_session_policy.up.sql
var browserSessionPolicy string

//go:embed 000005_link_lifetime_policy.up.sql
var linkLifetimePolicy string

//go:embed 000006_credential_lifetime_policy.up.sql
var credentialLifetimePolicy string

//go:embed 000007_login_budget_policy.up.sql
var loginBudgetPolicy string

//go:embed 000008_frontend_policy.up.sql
var frontendPolicy string

//go:embed 000009_operation_budgets_policy.up.sql
var operationBudgetsPolicy string

const AuthVersion = 3

func InitialAuth() string {
	return initialAuth + "\n" + settingsSource + "\n" + emailOTPPolicy
}

func StandaloneMigrations() string {
	return browserSessionPolicy + "\n" + linkLifetimePolicy + "\n" + credentialLifetimePolicy + "\n" + loginBudgetPolicy + "\n" + frontendPolicy + "\n" + operationBudgetsPolicy
}
