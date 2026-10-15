package router

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
)

type contractProvisioning struct {
	calls   int
	err     error
	reused  bool
	input   accountservice.ProvisionInput
	reissue accountservice.InvitationReissueInput
}

func (s *contractProvisioning) Provision(_ context.Context, input accountservice.ProvisionInput) (*accountservice.ProvisionResult, error) {
	s.calls++
	s.input = input
	return &accountservice.ProvisionResult{UserID: "22222222-2222-4222-8222-222222222222", Reused: s.reused}, s.err
}

func (s *contractProvisioning) ReissueInvitation(_ context.Context, input accountservice.InvitationReissueInput) (*accountservice.ProvisionResult, error) {
	s.calls++
	s.reissue = input
	return &accountservice.ProvisionResult{UserID: input.UserID, Reused: s.reused}, s.err
}

type contractTemporaryAdmin struct {
	calls   int
	err     error
	reused  bool
	input   passwordservice.TemporaryProvisionInput
	reissue passwordservice.TemporaryReissueInput
}

func (s *contractTemporaryAdmin) Provision(_ context.Context, input passwordservice.TemporaryProvisionInput) (*passwordservice.TemporaryIssueResult, error) {
	s.calls++
	s.input = input
	return &passwordservice.TemporaryIssueResult{UserID: "22222222-2222-4222-8222-222222222222", Reused: s.reused, ExpiresAt: time.Now().Add(time.Hour), Password: "one-time-synthetic-secret"}, s.err
}

func (s *contractTemporaryAdmin) Reissue(_ context.Context, input passwordservice.TemporaryReissueInput) (*passwordservice.TemporaryIssueResult, error) {
	s.calls++
	s.reissue = input
	return &passwordservice.TemporaryIssueResult{UserID: input.UserID, Reused: s.reused, Password: "one-time-synthetic-secret"}, s.err
}

func TestProvisioningHTTPContracts(t *testing.T) {
	for _, endpoint := range []struct {
		path              string
		create, temporary bool
	}{
		{"/api/v1/admin/users", true, false},
		{"/api/v1/admin/users/22222222-2222-4222-8222-222222222222/invitation", false, false},
		{"/api/v1/admin/users/temporary-password", true, true},
		{"/api/v1/admin/users/22222222-2222-4222-8222-222222222222/temporary-password", false, true},
	} {
		t.Run(endpoint.path, func(t *testing.T) {
			for _, tc := range []struct {
				name, method, origin, body string
				cookie, reused             bool
				err                        error
				status                     int
			}{
				{"success", "POST", "https://localhost:8443", `{}`, true, false, nil, 200},
				{"replay", "POST", "https://localhost:8443", `{}`, true, true, nil, 200},
				{"unauthorized", "POST", "https://localhost:8443", `{}`, false, false, nil, 401},
				{"origin", "POST", "https://evil.example", `{}`, true, false, nil, 403},
				{"no origin", "POST", "", `{}`, true, false, nil, 403},
				{"GET", "GET", "https://localhost:8443", "", true, false, nil, 405},
				{"bad JSON", "POST", "https://localhost:8443", `{`, true, false, nil, 400},
				{"spoofed actor", "POST", "https://localhost:8443", `{"actor":{"userId":"forged"}}`, true, false, nil, 400},
				{"roles", "POST", "https://localhost:8443", `{"roles":["super_admin"]}`, true, false, nil, 400},
				{"verification", "POST", "https://localhost:8443", `{"verified":true}`, true, false, nil, 400},
				{"permission", "POST", "https://localhost:8443", `{}`, true, false, accessdomain.ErrForbidden, 403},
				{"fresh proof", "POST", "https://localhost:8443", `{}`, true, false, accessdomain.ErrFreshAuthRequired, 403},
				{"conflict", "POST", "https://localhost:8443", `{}`, true, false, accountdomain.ErrProvisionConflict, 409},
				{"dependency", "POST", "https://localhost:8443", `{}`, true, false, errors.New("password=sensitive"), 503},
			} {
				t.Run(tc.name, func(t *testing.T) {
					s := &contractProvisioning{err: tc.err, reused: tc.reused}
					temp := &contractTemporaryAdmin{err: tc.err, reused: tc.reused}
					h := contractHandlers("prod")
					h.Provisioning = accounthttp.NewProvisioning(s, zap.NewNop())
					h.TemporaryAdmin = passwordhttp.NewTemporaryAdmin(temp, zap.NewNop())
					req := httptest.NewRequest(tc.method, endpoint.path, strings.NewReader(tc.body))
					req.Header.Set("Content-Type", "application/json")
					if tc.origin != "" {
						req.Header.Set("Origin", tc.origin)
					}
					if tc.cookie {
						req.AddCookie(&http.Cookie{Name: "__Host-session", Value: validCookieToken})
					}
					w := httptest.NewRecorder()
					New(h).ServeHTTP(w, req)
					want := tc.status
					if want == 200 && endpoint.create && !tc.reused {
						want = 201
					}
					if w.Code != want || len(w.Result().Cookies()) != 0 || strings.Contains(w.Body.String(), "sensitive") {
						t.Fatal("unsafe response", w.Code, w.Body.String())
					}
					if tc.method == "POST" && w.Header().Get("Cache-Control") != "no-store" {
						t.Fatal("missing no-store")
					}
					calls := s.calls + temp.calls
					if (tc.status >= 400 && tc.err == nil && calls != 0) || (tc.err != nil && calls != 1) {
						t.Fatal("unexpected service call", calls)
					}
					if tc.status == 200 && endpoint.temporary && strings.Contains(w.Body.String(), "one-time-synthetic-secret") == tc.reused {
						t.Fatal("one-time password/replay contract", w.Body.String())
					}
				})
			}
		})
	}
}

func TestProvisioningDisabledRoutes(t *testing.T) {
	for _, flag := range []string{"mfa", "invitation", "temporary"} {
		h := contractHandlers("prod")
		paths := []string{"/api/v1/admin/users", "/api/v1/admin/users/22222222-2222-4222-8222-222222222222/invitation"}
		tempPaths := []string{"/api/v1/admin/users/temporary-password", "/api/v1/admin/users/22222222-2222-4222-8222-222222222222/temporary-password"}
		switch flag {
		case "mfa":
			h.Config.MFA.Enabled = false
			paths = append(paths, tempPaths...)
		case "invitation":
			h.Config.Invitation.Enabled = false
		case "temporary":
			h.Config.TemporaryPassword.Enabled = false
			paths = tempPaths
		}
		for _, path := range paths {
			w := httptest.NewRecorder()
			New(h).ServeHTTP(w, httptest.NewRequest("POST", path, nil))
			if w.Code != 404 {
				t.Fatal("disabled route exposed", flag, path, w.Code)
			}
		}
	}
}

func TestProvisioningRateLimits(t *testing.T) {
	for _, temporary := range []bool{false, true} {
		h := contractHandlers("prod")
		path := "/api/v1/admin/users"
		if temporary {
			h.TemporaryAdmin = passwordhttp.NewTemporaryAdmin(&contractTemporaryAdmin{err: passworddomain.ErrRecoveryLimited}, zap.NewNop())
			path += "/temporary-password"
		} else {
			h.Provisioning = accounthttp.NewProvisioning(&contractProvisioning{err: accountdomain.ErrVerificationLimited}, zap.NewNop())
		}
		r := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://localhost:8443")
		r.AddCookie(&http.Cookie{Name: "__Host-session", Value: validCookieToken})
		w := httptest.NewRecorder()
		New(h).ServeHTTP(w, r)
		if w.Code != 429 || w.Header().Get("Retry-After") != "60" {
			t.Fatal("quota mapping", w.Code, w.Body.String())
		}
	}
}

func TestProvisioningRequestMapping(t *testing.T) {
	const key = "33333333-3333-4333-8333-333333333333"
	const target = "22222222-2222-4222-8222-222222222222"
	s, temp := &contractProvisioning{}, &contractTemporaryAdmin{}
	h := contractHandlers("prod")
	h.Provisioning = accounthttp.NewProvisioning(s, zap.NewNop())
	h.TemporaryAdmin = passwordhttp.NewTemporaryAdmin(temp, zap.NewNop())
	for _, path := range []string{"", "/" + target + "/invitation", "/temporary-password", "/" + target + "/temporary-password"} {
		body := `{"idempotencyKey":"` + key + `"}`
		if path == "" {
			body = `{"idempotencyKey":"` + key + `","email":" USER@example.com ","invite":true}`
		}
		if path == "/temporary-password" {
			body = `{"idempotencyKey":"` + key + `","email":" USER@example.com "}`
		}
		r := httptest.NewRequest("POST", "/api/v1/admin/users"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://localhost:8443")
		r.AddCookie(&http.Cookie{Name: "__Host-session", Value: validCookieToken})
		w := httptest.NewRecorder()
		New(h).ServeHTTP(w, r)
		if w.Code != 200 && w.Code != 201 {
			t.Fatal("request failed", w.Code, w.Body.String())
		}
	}
	if s.input.Actor.UserID != "user-1" || s.input.Actor.TokenHash != "hash" || s.input.IdempotencyKey != key || s.input.Email != " USER@example.com " || !s.input.Invite {
		t.Fatal("creation input lost authenticated authority or transport normalized domain input")
	}
	if string(s.reissue.UserID) != target || s.reissue.Actor != s.input.Actor || s.reissue.IdempotencyKey != key {
		t.Fatal("invitation input lost target/key/authority")
	}
	if temp.input.Actor != s.input.Actor || temp.input.IdempotencyKey != key || temp.input.Email != " USER@example.com " || temp.reissue.Actor != s.input.Actor || string(temp.reissue.UserID) != target || temp.reissue.IdempotencyKey != key {
		t.Fatal("temporary issue mapping")
	}
}
