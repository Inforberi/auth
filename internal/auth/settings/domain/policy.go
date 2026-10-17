package domain

import "errors"

type EmailVerification string

const (
	VerificationDisabled EmailVerification = "disabled"
	VerificationOptional EmailVerification = "optional"
	VerificationRequired EmailVerification = "required"
)

var (
	ErrInvalidPolicy  = errors.New("invalid auth policy")
	ErrPolicyConflict = errors.New("auth policy version conflict")
	ErrNotInitialized = errors.New("auth policy not initialized")
	ErrMethodNotReady = errors.New("auth method is not ready on this instance")
)

type PublicMethods struct {
	Password bool
	EmailOTP bool
	Google   bool
	Telegram bool
}

type PublicRegistration struct {
	Enabled  bool
	Google   bool
	Telegram bool
}

// Policy configures public authentication; administrative password and MFA are not switches here.
type Policy struct {
	Methods                   PublicMethods
	Registration              PublicRegistration
	PasswordEmailVerification EmailVerification
}

type Snapshot struct {
	Version int64
	Policy  Policy
}

func (p Policy) Validate() error {
	switch p.PasswordEmailVerification {
	case VerificationDisabled, VerificationOptional, VerificationRequired:
		return nil
	default:
		return ErrInvalidPolicy
	}
}

func (p Policy) RequireAvailable(available PublicMethods) error {
	if p.Methods.Password && !available.Password || p.Methods.EmailOTP && !available.EmailOTP ||
		p.Methods.Google && !available.Google || p.Methods.Telegram && !available.Telegram {
		return ErrMethodNotReady
	}
	return nil
}

func (p Policy) RestrictsLogin(previous Policy) bool {
	return previous.Methods.Password && !p.Methods.Password ||
		previous.Methods.EmailOTP && !p.Methods.EmailOTP ||
		previous.Methods.Google && !p.Methods.Google ||
		previous.Methods.Telegram && !p.Methods.Telegram ||
		p.Methods.Password && previous.PasswordEmailVerification != VerificationRequired && p.PasswordEmailVerification == VerificationRequired
}
