package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

type changeServiceStub struct {
	err                                 error
	calls                               int
	user                                domain.UserID
	session, email, password, token, ip string
}

func (s *changeServiceStub) Request(_ context.Context, user domain.UserID, session, email, password, ip string) error {
	s.calls++
	s.user, s.session, s.email, s.password, s.ip = user, session, email, password, ip
	return s.err
}

func (s *changeServiceStub) Confirm(_ context.Context, token, ip string) error {
	s.calls++
	s.token, s.ip = token, ip
	return s.err
}

func (s *changeServiceStub) Report(ctx context.Context, token, ip string) error {
	return s.Confirm(ctx, token, ip)
}

func TestEmailChangeHTTP(t *testing.T) {
	for _, tc := range []struct {
		name, action, body, code string
		auth                     bool
		err                      error
		status                   int
	}{
		{"request", "request", `{"email":"new@example.com","password":"current"}`, "accepted", true, nil, 202},
		{"unauthenticated", "request", `{}`, "unauthorized", false, nil, 401},
		{"fresh auth", "request", `{}`, "fresh_auth_required", true, domain.ErrFreshAuthRequired, 401},
		{"pending", "request", `{}`, "email_change_pending", true, domain.ErrEmailChangePending, 409},
		{"format", "request", `{"email":"new@example.com","unknown":1}`, "invalid_json", true, nil, 400},
		{"email validation belongs to service", "request", `{"email":"bad"}`, "invalid_email", true, domain.ErrEmailInvalid, 400},
		{"confirm", "confirm", `{"token":"confirm-token"}`, "ok", false, nil, 200},
		{"report", "report", `{"token":"report-token"}`, "ok", false, nil, 200},
		{"replay", "confirm", `{"token":"used"}`, "invalid_email_change", false, domain.ErrInvalidEmailChange, 400},
		{"limited", "report", `{"token":"token"}`, "rate_limited", false, domain.ErrVerificationLimited, 429},
		{"dependency", "report", `{"token":"token"}`, "temporarily_unavailable", false, errors.New("secret database/token details"), 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &changeServiceStub{err: tc.err}
			h := NewEmailChange(svc, zap.NewNop())
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-Forwarded-For", "forged")
			r.RemoteAddr = "127.0.0.1:1234"
			if tc.auth {
				r = r.WithContext(sessionhttp.SetAuthContext(r.Context(), sessionhttp.Auth{UserID: "caller", TokenHash: "hash"}))
			}
			w := httptest.NewRecorder()
			switch tc.action {
			case "request":
				h.Request(w, r)
			case "confirm":
				h.Confirm(w, r)
			case "report":
				h.Report(w, r)
			}
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.code) {
				t.Fatal(w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "current") || strings.Contains(w.Body.String(), "report-token") {
				t.Fatal("private data in response")
			}
			if svc.calls > 0 && svc.ip != "127.0.0.1" {
				t.Fatal("untrusted forwarded IP")
			}
			if tc.action == "request" && tc.name == "request" && (svc.user != "caller" || svc.session != "hash" || svc.password != "current") {
				t.Fatal("lost fresh auth context")
			}
			if tc.status == 200 && (tc.action == "confirm" || tc.action == "report") && !strings.Contains(w.Header().Get("Set-Cookie"), "Max-Age=0") {
				t.Fatal("cookie not cleared")
			}
		})
	}
}
