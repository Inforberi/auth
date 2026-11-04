package auth

import (
	"go.uber.org/zap"

	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/native/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type nativeLoginDependencies struct {
	password *passwordservice.PasswordService
	mfa      *mfaApp
	email    *emailOTPApp
}

func assembleNativeTokens(tokens *tokenApp, password *passwordservice.PasswordService, mfa *mfaApp, email *emailOTPApp, cfg *config.Config, log *zap.Logger) (*tokennativehttp.NativeHandler, error) {
	if !cfg.JWT.NativeEnabled {
		return nil, nil
	}
	if !cfg.JWT.Enabled || !cfg.MFA.Enabled || tokens == nil || password == nil || mfa == nil || mfa.login == nil {
		return nil, authjwt.ErrConfiguration
	}
	login, err := service.NewNativeLogin(tokens.service, mfa.login)
	if err != nil {
		return nil, err
	}
	primary, err := service.NewNativePasswordLogin(login, password)
	if err != nil {
		return nil, err
	}
	services := tokennativehttp.NativeServices{Password: primary, MFA: login, Enrollment: mfa.login, Tokens: tokens.service}
	if cfg.EmailOTP.Enabled {
		if email == nil || email.service == nil {
			return nil, authjwt.ErrConfiguration
		}
		services.Email, err = service.NewNativeEmailLogin(login, email.service)
		if err != nil {
			return nil, err
		}
	}
	return tokennativehttp.NewNative(services, log), nil
}
