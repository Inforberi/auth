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

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

type contractMFARecovery struct {
	calls    int
	err      error
	start    mfaservice.StartRecoveryInput
	complete mfaservice.CompleteRecoveryInput
}

func (s *contractMFARecovery) Start(_ context.Context, input mfaservice.StartRecoveryInput) (*mfaservice.RecoveryCandidate, error) {
	s.calls++
	s.start = input
	if s.err != nil {
		return nil, s.err
	}
	if input.Binding != mfaBrowser {
		return nil, mfadomain.ErrInvalidCode
	}
	return &mfaservice.RecoveryCandidate{RequestID: "22222222-2222-4222-8222-222222222222", Secret: "new-candidate-secret", URI: "otpauth://totp/recovery", ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func (s *contractMFARecovery) Complete(_ context.Context, input mfaservice.CompleteRecoveryInput) (*mfaservice.RecoveryCodes, error) {
	s.calls++
	s.complete = input
	if s.err != nil {
		return nil, s.err
	}
	if input.Binding != mfaBrowser {
		return nil, mfadomain.ErrInvalidCode
	}
	return &mfaservice.RecoveryCodes{Codes: []string{"one-time-recovery"}}, nil
}

func TestMFARecoveryHTTPContract(t *testing.T) {
	for _, action := range []string{"start", "complete"} {
		for _, mode := range []string{"valid", "missing-cookie", "duplicate-cookie", "foreign-cookie", "origin", "missing-origin", "get", "disabled", "mfa-disabled", "nil-service", "unknown-field", "limited", "unapproved", "dependency"} {
			t.Run(action+"-"+mode, func(t *testing.T) {
				stub := &contractMFARecovery{}
				h := contractHandlers("prod")
				h.MFA = mfahttp.NewWithRecovery(&contractMFA{}, &contractMFA{}, stub, zap.NewNop())
				body := `{"challenge":"primary-challenge"}`
				if action == "complete" {
					body = `{"requestId":"22222222-2222-4222-8222-222222222222","challenge":"primary-challenge","code":"123456"}`
				}
				method := "POST"
				want := 200
				call := true
				switch mode {
				case "missing-cookie", "duplicate-cookie", "foreign-cookie":
					want = 400
				case "origin", "missing-origin":
					want, call = 403, false
				case "get":
					method, want, call = "GET", 405, false
				case "disabled":
					h.Config.MFA.RecoveryEnabled = false
					want, call = 404, false
				case "mfa-disabled":
					h.Config.MFA.Enabled = false
					want, call = 404, false
				case "nil-service":
					h.MFA = mfahttp.New(&contractMFA{}, &contractMFA{}, zap.NewNop())
					want, call = 503, false
				case "unknown-field":
					body = strings.TrimSuffix(body, "}") + `,"approved":true}`
					want, call = 400, false
				case "limited":
					stub.err = mfadomain.ErrLimited
					want = 429
				case "unapproved":
					stub.err = mfadomain.ErrInvalidCode
					want = 400
				case "dependency":
					stub.err = errors.New("private-secret-DSN")
					want = 503
				}
				r := httptest.NewRequest(method, "https://localhost:8443/api/v1/auth/mfa/recovery/"+action, strings.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", "https://localhost:8443")
				if mode == "origin" {
					r.Header.Set("Origin", "https://evil.example")
				}
				if mode == "missing-origin" {
					r.Header.Del("Origin")
				}
				if mode != "missing-cookie" {
					binding := mfaBrowser
					if mode == "foreign-cookie" {
						binding = "foreign"
					}
					r.AddCookie(&http.Cookie{Name: mfahttp.LoginCookie, Value: binding})
				}
				if mode == "duplicate-cookie" {
					r.AddCookie(&http.Cookie{Name: mfahttp.LoginCookie, Value: mfaBrowser})
				}
				w := httptest.NewRecorder()
				New(h).ServeHTTP(w, r)
				if w.Code != want || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "private-secret") {
					t.Fatal(w.Code, w.Body.String())
				}
				if (stub.calls == 1) != call {
					t.Fatal("unexpected recovery call count", stub.calls)
				}
				if mode == "valid" {
					if action == "start" {
						if stub.start.Token != "primary-challenge" || stub.start.Binding != mfaBrowser || !strings.Contains(w.Body.String(), "new-candidate-secret") || len(w.Result().Cookies()) != 0 {
							t.Fatal("start contract")
						}
					} else {
						if stub.complete.Token != "primary-challenge" || stub.complete.Binding != mfaBrowser || stub.complete.Code != "123456" || !strings.Contains(w.Body.String(), "one-time-recovery") {
							t.Fatal("completion contract")
						}
						cookies := w.Result().Cookies()
						if len(cookies) != 2 {
							t.Fatal("cookies not cleared", cookies)
						}
						for _, cookie := range cookies {
							if (cookie.Name != mfahttp.LoginCookie && cookie.Name != sessionhttp.SessionCookieName) || cookie.MaxAge != -1 || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" {
								t.Fatal("recovery issued a session", cookie)
							}
						}
					}
				} else if len(w.Result().Cookies()) != 0 {
					t.Fatal("failed recovery modified cookies")
				}
				if mode == "limited" && w.Header().Get("Retry-After") != "60" {
					t.Fatal("missing retry budget")
				}
			})
		}
	}
}
