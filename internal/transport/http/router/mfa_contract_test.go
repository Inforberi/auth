package router

import (
	"context"
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

const mfaBrowser = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type contractMFA struct {
	calls int
	err   error
	proof mfaservice.Proof
	input mfaservice.CompleteLoginInput
}

func (f *contractMFA) StartEnrollment(_ context.Context, p mfaservice.Proof) (*mfaservice.Enrollment, error) {
	f.calls++
	f.proof = p
	return &mfaservice.Enrollment{Token: "enrollment-token", Secret: "secret", URI: "otpauth://totp/test", ExpiresAt: time.Now().Add(time.Minute)}, f.err
}

func (f *contractMFA) ConfirmEnrollment(_ context.Context, p mfaservice.ConfirmInput) (*mfaservice.RecoveryCodes, error) {
	f.calls++
	f.proof = p.Proof
	return &mfaservice.RecoveryCodes{Codes: []string{"recovery-secret"}}, f.err
}

func (f *contractMFA) StartReplacement(ctx context.Context, p mfaservice.Proof) (*mfaservice.Enrollment, error) {
	return f.StartEnrollment(ctx, p)
}

func (f *contractMFA) ConfirmReplacement(ctx context.Context, p mfaservice.ConfirmInput) (*mfaservice.RecoveryCodes, error) {
	return f.ConfirmEnrollment(ctx, p)
}

func (f *contractMFA) StepUp(_ context.Context, p mfaservice.StepUpInput) (*mfaservice.StepUpResult, error) {
	f.calls++
	f.proof = p.Proof
	return &mfaservice.StepUpResult{Token: mfaBrowser, VerifiedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}, f.err
}

func (f *contractMFA) Disable(_ context.Context, p mfaservice.Proof) error {
	f.calls++
	f.proof = p
	return f.err
}

func (f *contractMFA) RegenerateRecovery(_ context.Context, p mfaservice.Proof) (*mfaservice.RecoveryCodes, error) {
	f.calls++
	f.proof = p
	return &mfaservice.RecoveryCodes{Codes: []string{"recovery-secret"}}, f.err
}

func (f *contractMFA) Complete(_ context.Context, p mfaservice.CompleteLoginInput) (*mfaservice.LoginSession, error) {
	f.calls++
	f.input = p
	if f.err != nil {
		return nil, f.err
	}
	if p.Binding != mfaBrowser {
		return nil, mfadomain.ErrInvalidCode
	}
	return &mfaservice.LoginSession{Token: mfaBrowser, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func TestMFAOwnerRoutesAndOrigin(t *testing.T) {
	for _, path := range []string{"/mfa/totp/enrollment", "/mfa/totp/enrollment/confirm", "/mfa/totp/replacement", "/mfa/totp/replacement/confirm", "/mfa/step-up", "/mfa/recovery-codes/regenerate", "/mfa/totp"} {
		method := "POST"
		if path == "/mfa/totp" {
			method = "DELETE"
		}
		for _, mode := range []string{"valid", "origin", "session", "disabled", "error"} {
			t.Run(path+"-"+mode, func(t *testing.T) {
				stub := &contractMFA{}
				h := contractHandlers("prod")
				h.MFA = mfahttp.New(stub, stub, zap.NewNop())
				if mode == "disabled" {
					h.Config.MFA.Enabled = false
				}
				if mode == "error" {
					stub.err = mfadomain.ErrProofRequired
				}
				body := `{}`
				if strings.HasSuffix(path, "/confirm") {
					body = `{"token":"enrollment-token","code":"123456"}`
				}
				if path == "/mfa/step-up" {
					body = `{"code":"123456"}`
				}
				r := httptest.NewRequest(method, "https://localhost:8443/api/v1/auth"+path, strings.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", "https://localhost:8443")
				if mode == "origin" {
					r.Header.Set("Origin", "https://evil.example")
				}
				if mode != "session" {
					r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: mfaBrowser})
				}
				w := httptest.NewRecorder()
				New(h).ServeHTTP(w, r)
				want := 200
				switch mode {
				case "origin", "error":
					want = 403
				case "session":
					want = 401
				case "disabled":
					want = 404
				}
				if w.Code != want || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal(w.Code, w.Body.String())
				}
				if mode == "valid" || mode == "error" {
					if stub.calls != 1 || stub.proof.AuthVersion != 7 || stub.proof.TokenHash == "" || stub.proof.UserID == "" {
						t.Fatal("owner context missing", stub)
					}
				} else if stub.calls != 0 {
					t.Fatal("rejected request reached MFA service")
				}
				if mode == "error" && len(w.Result().Cookies()) != 0 {
					t.Fatal("failure modified session cookie")
				}
			})
		}
	}
}

func TestMFACompletionCookiesAndPayload(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "duplicate", "foreign", "origin", "client-user", "get", "dependency"} {
		t.Run(mode, func(t *testing.T) {
			stub := &contractMFA{}
			if mode == "dependency" {
				stub.err = mfadomain.ErrUnavailable
			}
			h := contractHandlers("prod")
			h.MFA = mfahttp.New(stub, stub, zap.NewNop())
			body := `{"challenge":"challenge-token","code":"123456"}`
			if mode == "client-user" {
				body = `{"challenge":"challenge-token","code":"123456","userId":"attacker"}`
			}
			method := "POST"
			if mode == "get" {
				method = "GET"
			}
			r := httptest.NewRequest(method, "https://localhost:8443/api/v1/auth/mfa/login/complete", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", "https://localhost:8443")
			if mode == "origin" {
				r.Header.Set("Origin", "https://evil.example")
			}
			if mode != "missing" {
				value := mfaBrowser
				if mode == "foreign" {
					value = "foreign"
				}
				r.AddCookie(&http.Cookie{Name: mfahttp.LoginCookie, Value: value})
			}
			if mode == "duplicate" {
				r.AddCookie(&http.Cookie{Name: mfahttp.LoginCookie, Value: mfaBrowser})
			}
			w := httptest.NewRecorder()
			New(h).ServeHTTP(w, r)
			want := 400
			switch mode {
			case "valid":
				want = 200
			case "origin":
				want = 403
			case "get":
				want = 405
			case "dependency":
				want = 503
			}
			if w.Code != want {
				t.Fatal(w.Code, w.Body.String())
			}
			cookies := w.Result().Cookies()
			if mode == "valid" {
				if len(cookies) != 2 || !cookies[1].Secure || !cookies[1].HttpOnly || cookies[1].Name != sessionhttp.SessionCookieName || strings.Contains(w.Body.String(), mfaBrowser) {
					t.Fatal("session cookie/secret leak", cookies, w.Body.String())
				}
			} else if len(cookies) != 0 {
				t.Fatal("failed completion issued cookies")
			}
		})
	}
}

func TestMFAChallengeNeverIssuesSession(t *testing.T) {
	w := httptest.NewRecorder()
	mfahttp.RespondChallenge(w, &mfaservice.LoginChallenge{Token: "challenge-token", Binding: mfaBrowser, ExpiresAt: time.Now().Add(time.Minute)})
	if w.Code != 202 || strings.Contains(w.Body.String(), mfaBrowser) {
		t.Fatal("challenge leaks browser binding")
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 2 || cookies[0].MaxAge != -1 || cookies[1].Name != mfahttp.LoginCookie || !cookies[1].Secure || !cookies[1].HttpOnly || cookies[1].Path != "/" || cookies[1].Domain != "" {
		t.Fatal("challenge/session cookies", cookies)
	}
}
