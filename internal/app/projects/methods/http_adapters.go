package methods

import (
	"context"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passwordprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/service"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type ProjectPasswordReauthenticationHTTP struct{ *ProjectPassword }

func (s ProjectPasswordReauthenticationHTTP) Confirm(ctx context.Context, user accountdomain.UserID, hash, password, ip string) (*passwordservice.ReauthenticationResult, error) {
	return s.ConfirmReauthentication(ctx, user, hash, password, ip)
}

type ProjectTemporaryHTTP struct{ *ProjectPassword }

func (s ProjectTemporaryHTTP) Login(ctx context.Context, email, password, ip string) (*passwordprovisioning.TemporaryLoginResult, error) {
	return s.BeginTemporaryPassword(ctx, email, password, ip)
}

func (s ProjectTemporaryHTTP) Complete(ctx context.Context, token, password, confirmation, ip string) error {
	return s.CompleteTemporaryPassword(ctx, token, password, confirmation, ip)
}

type ProjectEmailMFAPrimary struct{ *ProjectPassword }

func (s ProjectEmailMFAPrimary) Authenticate(ctx context.Context, input passwordservice.LoginInput) (mfaservice.PrimaryProof, error) {
	if s.ProjectPassword == nil {
		return mfaservice.PrimaryProof{}, mfadomain.ErrUnavailable
	}
	return s.ProjectPassword.Authenticate(ctx, input)
}

type ProjectTemporaryAdminHTTP struct{ *ProjectPassword }

func (s ProjectTemporaryAdminHTTP) Provision(ctx context.Context, input passwordprovisioning.TemporaryProvisionInput) (*passwordprovisioning.TemporaryIssueResult, error) {
	return s.ProvisionTemporaryPassword(ctx, input)
}

func (s ProjectTemporaryAdminHTTP) Reissue(ctx context.Context, input passwordprovisioning.TemporaryReissueInput) (*passwordprovisioning.TemporaryIssueResult, error) {
	return s.ReissueTemporaryPassword(ctx, input)
}
