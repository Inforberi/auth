package account

import (
	"context"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type ProjectVerificationHTTP struct{ *ProjectEmail }

func (s ProjectVerificationHTTP) Resend(ctx context.Context, email, ip string) error {
	return s.ResendVerification(ctx, email, ip)
}

func (s ProjectVerificationHTTP) Confirm(ctx context.Context, token, ip string) error {
	return s.ConfirmVerification(ctx, token, ip)
}

type ProjectRecoveryHTTP struct{ *ProjectEmail }

func (s ProjectRecoveryHTTP) Forgot(ctx context.Context, email, ip string) error {
	return s.ForgotPassword(ctx, email, ip)
}

func (s ProjectRecoveryHTTP) Reset(ctx context.Context, token, password, confirmation, ip string) error {
	return s.ResetPassword(ctx, token, password, confirmation, ip)
}

type ProjectBindingHTTP struct{ *ProjectEmail }

func (s ProjectBindingHTTP) Request(ctx context.Context, input accountemail.EmailBindingInput) (time.Time, error) {
	return s.RequestEmailBinding(ctx, input)
}

func (s ProjectBindingHTTP) Confirm(ctx context.Context, proof mfaservice.Proof, code, ip string) error {
	return s.ConfirmEmailBinding(ctx, proof, code, ip)
}

type ProjectChangeHTTP struct{ *ProjectEmail }

func (s ProjectChangeHTTP) Request(ctx context.Context, user accountdomain.UserID, hash, email, password, ip string) error {
	return s.RequestEmailChange(ctx, user, hash, email, password, ip)
}

func (s ProjectChangeHTTP) Confirm(ctx context.Context, token, ip string) error {
	return s.ConfirmEmailChange(ctx, token, ip)
}

func (s ProjectChangeHTTP) Report(ctx context.Context, token, ip string) error {
	return s.ReportEmailChange(ctx, token, ip)
}

type ProjectProtectedRecoveryHTTP struct{ *ProjectEmail }

func (s ProjectProtectedRecoveryHTTP) Recover(ctx context.Context, token, password, confirmation, ip string) error {
	return s.RecoverEmailChange(ctx, token, password, confirmation, ip)
}

type ProjectProvisioningHTTP struct{ *ProjectEmail }

func (s ProjectProvisioningHTTP) Provision(ctx context.Context, input accountprovisioning.ProvisionInput) (*accountprovisioning.ProvisionResult, error) {
	return s.ProvisionUser(ctx, input)
}

type ProjectInvitationActivationHTTP struct{ *ProjectEmail }

func (s ProjectInvitationActivationHTTP) Activate(ctx context.Context, token, password, confirmation, ip string) error {
	return s.ActivateInvitation(ctx, token, password, confirmation, ip)
}
