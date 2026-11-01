package mfahttp

import (
	"context"
	"net/http"
	"strings"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	otpdomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type emailPreparation interface {
	Request(context.Context, service.Proof, string, string) (*otpservice.RequestedCode, error)
	Confirm(context.Context, otpservice.EmailPreparationConfirmation) (*otpservice.ReauthenticatedSession, error)
}

type emailFactors interface {
	Status(context.Context, service.Proof) (*domain.EmailFactor, error)
	Enable(context.Context, service.Proof) error
	Disable(context.Context, service.Proof) error
}

type emailLogin interface {
	Start(context.Context, service.PrimaryProof, string) (*service.LoginChallenge, error)
	Complete(context.Context, service.CompleteLoginInput) (*service.LoginSession, error)
}

type emailPassword interface {
	Authenticate(context.Context, passwordservice.LoginInput) (service.PrimaryProof, error)
}

type EmailHandler struct {
	preparation emailPreparation
	factors     emailFactors
	login       emailLogin
	password    emailPassword
	log         *zap.Logger
	cookieName  string
}

func NewEmail(preparation emailPreparation, factors emailFactors, login emailLogin, password emailPassword, log *zap.Logger) (*EmailHandler, error) {
	return NewEmailWithCookie(preparation, factors, login, password, log, EmailLoginCookie)
}

func NewEmailWithCookie(preparation emailPreparation, factors emailFactors, login emailLogin, password emailPassword, log *zap.Logger, cookieName string) (*EmailHandler, error) {
	cookie := &http.Cookie{Name: cookieName, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	if preparation == nil || factors == nil || login == nil || password == nil || !strings.HasPrefix(cookieName, "__Host-") || len(cookieName) > 100 || cookie.Valid() != nil {
		return nil, domain.ErrUnavailable
	}
	return &EmailHandler{preparation: preparation, factors: factors, login: login, password: password, log: log, cookieName: cookieName}, nil
}

var emailMFAErrors = append([]httpx.ErrorRule{
	httpx.MatchError(accountdomain.ErrEmailRequired, 400, "email_required", "email required"),
	httpx.MatchError(accountdomain.ErrEmailInvalid, 400, "invalid_email", "invalid email"),
	httpx.MatchError(passworddomain.ErrInvalidEmail, 400, "invalid_email", "invalid email"),
	httpx.MatchError(passworddomain.ErrPasswordRequired, 400, "password_required", "password required"),
	httpx.MatchError(passworddomain.ErrInvalidEmailOrPassword, 400, "invalid_credentials", "invalid credentials"),
	httpx.MatchError(passworddomain.ErrLoginUnavailable, 503, "temporarily_unavailable", "temporarily unavailable"),
	httpx.MatchError(passworddomain.ErrHashBusy, 503, "temporarily_unavailable", "temporarily unavailable"),
	httpx.MatchError(otpdomain.ErrInvalidPreparation, 400, "invalid_email_factor", "invalid email factor proof"),
	{Target: otpdomain.ErrLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
	{Target: passworddomain.ErrLoginLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
}, mfaErrors...)

func (h *EmailHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	respondMFAError(w, r, h.log, err, emailMFAErrors)
}

func emailActionProof(w http.ResponseWriter, r *http.Request) (service.Proof, bool) {
	proof, ok := requestProof(w, r)
	if !ok {
		return service.Proof{}, false
	}
	if r.Body != nil && r.Body != http.NoBody {
		var input struct{}
		if err := httpx.DecodeJSON(w, r, &input); err != nil {
			httpx.Error(w, 400, "invalid_json", "this action accepts no fields")
			return service.Proof{}, false
		}
	}
	return proof, true
}
