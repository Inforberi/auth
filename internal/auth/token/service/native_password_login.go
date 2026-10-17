package service

import (
	"context"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type PasswordPrimary interface {
	Authenticate(context.Context, passwordservice.LoginInput) (mfaservice.PrimaryProof, error)
}

type NativePasswordLogin struct {
	login    *NativeLogin
	password PasswordPrimary
}

type NativePasswordInput struct {
	Email         string
	Password      string `json:"-"`
	Audience      string
	Scope         []accessdomain.PermissionKey
	UserAgent, IP string
}

func NewNativePasswordLogin(login *NativeLogin, password PasswordPrimary) (*NativePasswordLogin, error) {
	if login == nil || password == nil {
		return nil, authjwt.ErrConfiguration
	}
	return &NativePasswordLogin{login: login, password: password}, nil
}

func (s *NativePasswordLogin) Login(ctx context.Context, input NativePasswordInput) (*NativeLoginResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, scope, err := s.login.tokens.requestedResource(input.Audience, input.Scope)
	if err != nil {
		return nil, err
	}
	proof, err := s.password.Authenticate(ctx, passwordservice.LoginInput{Email: input.Email, Password: input.Password, UserAgent: input.UserAgent, IP: input.IP})
	if err != nil {
		return nil, err
	}
	return s.login.Begin(ctx, NativeInput{Proof: proof, Audience: input.Audience, Scope: scope, UserAgent: input.UserAgent, IP: input.IP})
}
