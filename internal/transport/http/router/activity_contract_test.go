package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

type contractActivity struct{}

func (contractActivity) Record(context.Context, accountdomain.UserID, string) (*sessionservice.ActivityResult, error) {
	return &sessionservice.ActivityResult{ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func TestActivityHasNoAutomaticRefresh(t *testing.T) {
	h := contractHandlers("prod")
	sessions := &securitySessions{}
	h.Middleware = sessionhttp.New(sessions, h.Logger)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/session/activity", nil)
	r.Header.Set("Origin", "https://localhost:8443")
	r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: validCookieToken})
	w := httptest.NewRecorder()
	New(h).ServeHTTP(w, r)
	if w.Code != 200 || sessions.refresh != 0 || sessions.noRefresh != 1 || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("activity used generic refresh", w.Code, sessions, w.Header())
	}
}
