package domain

func (r PolicyRuntime) CheckChange(before Snapshot, expected int64, next Policy) error {
	if before.Version != expected {
		return ErrPolicyConflict
	}
	if !r.Configured {
		return ErrMethodNotReady
	}
	if err := next.RequireAvailable(r.Methods); err != nil {
		return err
	}
	if next.TokenIssuance.SessionExchange && !r.Tokens.SessionExchange || next.TokenIssuance.Native && !r.Tokens.Native {
		return ErrMethodNotReady
	}
	if r.RequireStoredProviders && next.RequiresEmailDelivery() && !r.EmailDeliveryReady {
		return ErrMethodNotReady
	}
	if r.Dependencies != nil && next.Methods.Password && next.PasswordEmailVerification != VerificationDisabled && !r.VerificationReady {
		return ErrMethodNotReady
	}
	return nil
}
