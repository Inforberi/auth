package token

import (
	"go.uber.org/zap"

	methodapp "github.com/Inforberi/financial-intelligence/internal/app/auth/methods"
	mfaapp "github.com/Inforberi/financial-intelligence/internal/app/auth/mfa"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/native/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type NativeLoginDependencies struct {
	Password *passwordservice.PasswordService
	MFA      *mfaapp.App
	Email    *methodapp.EmailOTP
}

func assembleNativeTokens(tokens *App, password *passwordservice.PasswordService, mfa *mfaapp.App, email *methodapp.EmailOTP, cfg *config.Config, log *zap.Logger) (*tokennativehttp.NativeHandler, error) {
	if !cfg.JWT.NativeEnabled {
		return nil, nil
	}
	if !cfg.JWT.Enabled || !cfg.MFA.Enabled || tokens == nil || password == nil || mfa == nil || mfa.Login == nil {
		return nil, authjwt.ErrConfiguration
	}
	login, err := service.NewNativeLogin(tokens.service, mfa.Login)
	if err != nil {
		return nil, err
	}
	primary, err := service.NewNativePasswordLogin(login, password)
	if err != nil {
		return nil, err
	}
	services := tokennativehttp.NativeServices{Password: primary, MFA: login, Enrollment: mfa.Login, Tokens: tokens.service}
	if cfg.EmailOTP.Enabled {
		if email == nil || email.Service == nil {
			return nil, authjwt.ErrConfiguration
		}
		services.Email, err = service.NewNativeEmailLogin(login, email.Service)
		if err != nil {
			return nil, err
		}
	}
	return tokennativehttp.NewNative(services, log), nil
}
