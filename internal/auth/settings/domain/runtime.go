package domain

// PolicyRuntime contains trusted assembly facts, never values from a settings request.
type PolicyRuntime struct {
	Configured             bool
	Methods                PublicMethods
	Tokens                 TokenIssuance
	RequireStoredProviders bool
	EmailDeliveryReady     bool
}

func (p Policy) RequiresEmailDelivery() bool {
	return p.Methods.EmailOTP || p.Methods.Password && p.PasswordEmailVerification != VerificationDisabled
}
