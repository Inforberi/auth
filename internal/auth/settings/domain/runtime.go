package domain

// PolicyRuntime contains trusted assembly facts, never values from a settings request.
type PolicyRuntime struct {
	Configured             bool
	Methods                PublicMethods
	Tokens                 TokenIssuance
	RequireStoredProviders bool
	EmailDeliveryReady     bool
	VerificationReady      bool
	Dependencies           *DependencyVersions
}

type DependencyVersions struct{ SMTP, Google, Telegram int64 }

type FeatureReadiness struct {
	Feature string `json:"feature"`
	Ready   bool   `json:"ready"`
	Reason  string `json:"reason,omitempty"`
}

func (p Policy) RequiresEmailDelivery() bool {
	return p.Methods.EmailOTP || p.Methods.Password && p.PasswordEmailVerification != VerificationDisabled
}
