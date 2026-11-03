package mfaloginhttp

import (
	"context"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
)

type emailLogin interface {
	Start(context.Context, mfaservice.PrimaryProof, string) (*mfalogin.LoginChallenge, error)
	Complete(context.Context, mfalogin.CompleteLoginInput) (*mfalogin.LoginSession, error)
}

type EmailHandler struct {
	login      emailLogin
	password   mfahttp.Password
	log        *zap.Logger
	cookieName string
}

func NewEmail(login emailLogin, password mfahttp.Password, log *zap.Logger) (*EmailHandler, error) {
	return NewEmailWithCookie(login, password, log, EmailLoginCookie)
}

func NewEmailWithCookie(login emailLogin, password mfahttp.Password, log *zap.Logger, cookieName string) (*EmailHandler, error) {
	cookie := &http.Cookie{Name: cookieName, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	if login == nil || password == nil || !strings.HasPrefix(cookieName, "__Host-") || len(cookieName) > 100 || cookie.Valid() != nil {
		return nil, domain.ErrUnavailable
	}
	return &EmailHandler{login: login, password: password, log: log, cookieName: cookieName}, nil
}

func (h *EmailHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	mfahttp.RespondEmailError(w, r, h.log, err)
}
