package token

import (
	"context"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
)

type ProjectNativePasswordEmailMFAHTTP struct{ *ProjectTokens }

func (s ProjectNativePasswordEmailMFAHTTP) Login(ctx context.Context, input tokenservice.NativePasswordInput) (*tokenservice.NativeLoginResult, error) {
	return s.LoginPasswordEmailMFA(ctx, input)
}

type ProjectNativeEmailMFAHTTP struct{ *ProjectTokens }

func (s ProjectNativeEmailMFAHTTP) Complete(ctx context.Context, input mfalogin.CompleteLoginInput) (*tokenservice.RefreshResult, error) {
	return s.CompleteNativeEmailMFA(ctx, input)
}

type ProjectNativePasswordHTTP struct{ *ProjectTokens }

func (s ProjectNativePasswordHTTP) Login(ctx context.Context, input tokenservice.NativePasswordInput) (*tokenservice.NativeLoginResult, error) {
	return s.LoginPassword(ctx, input)
}

type ProjectNativeEmailHTTP struct{ *ProjectTokens }

func (s ProjectNativeEmailHTTP) Request(ctx context.Context, email, ip, audience string, scope []accessdomain.PermissionKey) (*otpservice.RequestedCode, error) {
	return s.RequestEmail(ctx, email, ip, audience, scope)
}

func (s ProjectNativeEmailHTTP) Confirm(ctx context.Context, input otpservice.ConfirmInput) (*tokenservice.NativeLoginResult, error) {
	return s.ConfirmEmail(ctx, input)
}

type ProjectNativeMFAHTTP struct{ *ProjectTokens }

func (s ProjectNativeMFAHTTP) Complete(ctx context.Context, input mfalogin.CompleteLoginInput) (*tokenservice.RefreshResult, error) {
	return s.CompleteNativeMFA(ctx, input)
}

func (s ProjectNativeMFAHTTP) StartNativeRequiredEnrollment(ctx context.Context, input mfalogin.LoginEnrollmentInput) (*mfaservice.Enrollment, error) {
	return s.StartNativeEnrollment(ctx, input)
}

func (s ProjectNativeMFAHTTP) ConfirmNativeRequiredEnrollment(ctx context.Context, input mfalogin.ConfirmLoginEnrollmentInput) (*mfaservice.RecoveryCodes, error) {
	return s.ConfirmNativeEnrollment(ctx, input)
}
