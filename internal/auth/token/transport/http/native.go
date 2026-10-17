package http

import (
	"context"
	"net/http"
	"time"

	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	emailservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type NativePassword interface {
	Login(context.Context, service.NativePasswordInput) (*service.NativeLoginResult, error)
}

type NativeEmail interface {
	Request(context.Context, string, string, string, []accessdomain.PermissionKey) (*emailservice.RequestedCode, error)
	Confirm(context.Context, emailservice.ConfirmInput) (*service.NativeLoginResult, error)
}

type NativeMFA interface {
	Complete(context.Context, mfaservice.CompleteLoginInput) (*service.RefreshResult, error)
}

type NativeEnrollment interface {
	StartNativeRequiredEnrollment(context.Context, mfaservice.LoginEnrollmentInput) (*mfaservice.Enrollment, error)
	ConfirmNativeRequiredEnrollment(context.Context, mfaservice.ConfirmLoginEnrollmentInput) (*mfaservice.RecoveryCodes, error)
}

type NativeTokens interface {
	Refresh(context.Context, service.RefreshInput) (*service.RefreshResult, error)
	Logout(context.Context, service.RefreshInput) error
}

type NativeServices struct {
	Password   NativePassword
	Email      NativeEmail
	MFA        NativeMFA
	Enrollment NativeEnrollment
	Tokens     NativeTokens
}

type NativeHandler struct {
	services NativeServices
	log      *zap.Logger
}

func NewNative(services NativeServices, log *zap.Logger) *NativeHandler {
	return &NativeHandler{services: services, log: log}
}

type NativeResponse struct {
	ExchangeResponse
	RefreshToken     string    `json:"refreshToken"`
	RefreshExpiresAt time.Time `json:"refreshExpiresAt"`
} // @name token_http.NativeResponse

type NativeChallengeResponse struct {
	Challenge string    `json:"challenge"`
	Binding   string    `json:"binding"`
	ExpiresAt time.Time `json:"expiresAt"`
	NextStep  string    `json:"nextStep" enums:"mfa,enrollment"`
} // @name token_http.NativeChallengeResponse

func (h *NativeHandler) writeLogin(w http.ResponseWriter, r *http.Request, result *service.NativeLoginResult) {
	if result == nil || result.Tokens != nil && result.Challenge != nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	if result.Challenge != nil {
		step := "mfa"
		if result.Challenge.EnrollmentRequired {
			step = "enrollment"
		}
		c := result.Challenge
		httpx.JSON(w, 202, NativeChallengeResponse{Challenge: c.Token, Binding: c.Binding, ExpiresAt: c.ExpiresAt, NextStep: step})
		return
	}
	h.writeTokens(w, r, result.Tokens)
}

func (h *NativeHandler) writeTokens(w http.ResponseWriter, r *http.Request, result *service.RefreshResult) {
	if result == nil || result.ExchangeResult == nil || result.SignedToken == nil || result.Raw == "" || result.RefreshToken == "" {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	httpx.JSON(w, 200, NativeResponse{ExchangeResponse: exchangeResponse(result.ExchangeResult), RefreshToken: result.RefreshToken, RefreshExpiresAt: result.RefreshExpiresAt})
}
