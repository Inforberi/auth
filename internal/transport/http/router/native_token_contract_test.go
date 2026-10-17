package router

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	emailservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/signing"
	tokenhttp "github.com/Inforberi/financial-intelligence/internal/auth/token/transport/http"
)

type nativeContract struct {
	calls      int
	input      any
	err        error
	challenge  bool
	enrollment bool
}

func nativeTokensResult() *tokenservice.RefreshResult {
	return &tokenservice.RefreshResult{ExchangeResult: &tokenservice.ExchangeResult{SignedToken: &signing.SignedToken{Raw: "synthetic-access", ExpiresAt: time.Now().Add(time.Minute)}, Audience: "orders", Scope: []accessdomain.PermissionKey{"orders.read"}}, RefreshToken: "synthetic-refresh", RefreshExpiresAt: time.Now().Add(time.Hour)}
}

func (s *nativeContract) result() (*tokenservice.NativeLoginResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.challenge {
		return &tokenservice.NativeLoginResult{Challenge: &mfaservice.LoginChallenge{Token: "native-challenge", Binding: "native-binding", ExpiresAt: time.Now().Add(time.Minute), EnrollmentRequired: s.enrollment}}, nil
	}
	return &tokenservice.NativeLoginResult{Tokens: nativeTokensResult()}, nil
}

func (s *nativeContract) Login(_ context.Context, input tokenservice.NativePasswordInput) (*tokenservice.NativeLoginResult, error) {
	s.calls++
	s.input = input
	return s.result()
}

func (s *nativeContract) Request(_ context.Context, email, ip, audience string, scope []accessdomain.PermissionKey) (*emailservice.RequestedCode, error) {
	s.calls++
	s.input = tokenservice.NativePasswordInput{Email: email, IP: ip, Audience: audience, Scope: scope}
	return &emailservice.RequestedCode{Binding: "native-email-binding", ExpiresAt: time.Now().Add(time.Minute)}, s.err
}

func (s *nativeContract) Confirm(_ context.Context, input emailservice.ConfirmInput) (*tokenservice.NativeLoginResult, error) {
	s.calls++
	s.input = input
	return s.result()
}

func (s *nativeContract) Complete(_ context.Context, input mfaservice.CompleteLoginInput) (*tokenservice.RefreshResult, error) {
	s.calls++
	s.input = input
	return nativeTokensResult(), s.err
}

func (s *nativeContract) StartNativeRequiredEnrollment(_ context.Context, input mfaservice.LoginEnrollmentInput) (*mfaservice.Enrollment, error) {
	s.calls++
	s.input = input
	return &mfaservice.Enrollment{Token: "enrollment", Secret: "synthetic-secret", URI: "otpauth://synthetic", ExpiresAt: time.Now().Add(time.Minute)}, s.err
}

func (s *nativeContract) ConfirmNativeRequiredEnrollment(_ context.Context, input mfaservice.ConfirmLoginEnrollmentInput) (*mfaservice.RecoveryCodes, error) {
	s.calls++
	s.input = input
	return &mfaservice.RecoveryCodes{Codes: []string{"synthetic-recovery"}}, s.err
}

func (s *nativeContract) Refresh(_ context.Context, input tokenservice.RefreshInput) (*tokenservice.RefreshResult, error) {
	s.calls++
	s.input = input
	return nativeTokensResult(), s.err
}

func (s *nativeContract) Logout(_ context.Context, input tokenservice.RefreshInput) error {
	s.calls++
	s.input = input
	return s.err
}

func nativeContractHandlers(s *nativeContract) Handlers {
	h := contractHandlers("test")
	h.Config.JWT.Enabled, h.Config.JWT.NativeEnabled = true, true
	h.NativeTokens = tokenhttp.NewNative(tokenhttp.NativeServices{Password: s, Email: s, MFA: s, Enrollment: s, Tokens: s}, zap.NewNop())
	return h
}

var nativeRequests = []struct {
	path, body string
	status     int
}{
	{"/native/password/login", `{"email":"user@example.test","password":"Password12345","audience":"orders","scope":["orders.read"]}`, 200},
	{"/native/email/request", `{"email":"user@example.test","audience":"orders","scope":["orders.read"]}`, 202},
	{"/native/email/confirm", `{"binding":"native-binding","code":"12345678"}`, 200},
	{"/native/mfa/complete", `{"challenge":"native-challenge","binding":"native-binding","code":"123456"}`, 200},
	{"/native/mfa/enrollment", `{"challenge":"native-challenge","binding":"native-binding"}`, 200},
	{"/native/mfa/enrollment/confirm", `{"challenge":"native-challenge","binding":"native-binding","token":"enrollment","code":"123456"}`, 200},
	{"/token/refresh", `{"refreshToken":"synthetic-refresh"}`, 200},
	{"/token/logout", `{"refreshToken":"synthetic-refresh"}`, 204},
}

func nativeRequest(router http.Handler, method, path, body string, headers http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/api/v1/auth"+path, strings.NewReader(body))
	r.RemoteAddr = "192.0.2.1:50000"
	r.Header = headers.Clone()
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	if r.Header.Get("Content-Type") == "" {
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("User-Agent", "native-test")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w
}

func TestNativeTokenTransport(t *testing.T) {
	for _, tc := range nativeRequests {
		t.Run(tc.path, func(t *testing.T) {
			for _, mode := range []string{"valid", "at limit", "origin", "allowed origin", "empty origin", "cookie", "malformed cookie", "authorization", "query", "preflight", "unknown", "duplicate", "case", "null", "array", "oversized", "trailing", "media", "disabled", "JWT disabled", "no handler"} {
				t.Run(mode, func(t *testing.T) {
					s := &nativeContract{}
					h := nativeContractHandlers(s)
					h.Config.Browser.CORSEnabled = true
					headers := make(http.Header)
					method, path, body, want := "POST", tc.path, tc.body, tc.status
					switch mode {
					case "at limit":
						body = strings.Repeat(" ", 8192-len(body)) + body
					case "origin":
						headers["Origin"] = []string{"https://evil.example"}
						want = 403
					case "allowed origin":
						headers["Origin"] = []string{"https://localhost:8443"}
						want = 403
					case "empty origin":
						headers["Origin"] = []string{""}
						want = 403
					case "cookie":
						headers["Cookie"] = []string{"__Host-session=synthetic"}
						want = 400
					case "malformed cookie":
						headers["Cookie"] = []string{"not a valid cookie"}
						want = 400
					case "authorization":
						headers["Authorization"] = []string{"Bearer synthetic"}
						want = 400
					case "query":
						path += "?refreshToken=synthetic"
						want = 400
					case "preflight":
						method = "OPTIONS"
						headers["Origin"] = []string{"https://localhost:8443"}
						headers["Access-Control-Request-Method"] = []string{"POST"}
						want = 403
					case "unknown":
						body = strings.TrimSuffix(body, "}") + `,"administrative":true}`
						want = 400
					case "duplicate":
						var fields map[string]json.RawMessage
						if err := json.Unmarshal([]byte(body), &fields); err != nil {
							t.Fatal(err)
						}
						for key, value := range fields {
							body = strings.TrimSuffix(body, "}") + `,"` + key + `":` + string(value) + `}`
							break
						}
						want = 400
					case "case":
						body = body[:2] + strings.ToUpper(body[2:3]) + body[3:]
						want = 400
					case "null":
						body = `null`
						want = 400
					case "array":
						body = `[]`
						want = 400
					case "oversized":
						body = strings.Repeat(" ", 8193) + body
						want = 400
					case "trailing":
						body += `{}`
						want = 400
					case "media":
						headers["Content-Type"] = []string{"text/plain"}
						want = 400
					case "disabled":
						h.Config.JWT.NativeEnabled = false
						headers["Origin"] = []string{"https://localhost:8443"}
						want = 404
					case "JWT disabled":
						h.Config.JWT.Enabled = false
						headers["Origin"] = []string{"https://localhost:8443"}
						want = 404
					case "no handler":
						h.NativeTokens = nil
						headers["Origin"] = []string{"https://localhost:8443"}
						want = 404
					}
					w := nativeRequest(New(h), method, path, body, headers)
					if w.Code != want || w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 {
						t.Fatal(w.Code, want, w.Body.String(), w.Header())
					}
					if mode == "valid" || mode == "at limit" {
						if s.calls != 1 {
							t.Fatal("native request did not reach service")
						}
					} else if s.calls != 0 {
						t.Fatal("rejected input reached service")
					}
					if mode != "disabled" && mode != "JWT disabled" && mode != "no handler" && w.Header().Get("Access-Control-Allow-Origin") != "" {
						t.Fatal("browser CORS leaked to native")
					}
				})
			}
		})
	}
}

func TestNativeRestrictedOutputAndInputs(t *testing.T) {
	for _, enrollment := range []bool{false, true} {
		s := &nativeContract{challenge: true, enrollment: enrollment}
		w := nativeRequest(New(nativeContractHandlers(s)), "POST", nativeRequests[0].path, nativeRequests[0].body, nil)
		var body map[string]any
		if json.Unmarshal(w.Body.Bytes(), &body) != nil || w.Code != 202 || len(body) != 4 || body["accessToken"] != nil || body["refreshToken"] != nil || body["binding"] != "native-binding" {
			t.Fatal(w.Code, w.Body.String())
		}
		want := "mfa"
		if enrollment {
			want = "enrollment"
		}
		if body["nextStep"] != want {
			t.Fatal(body)
		}
		input := s.input.(tokenservice.NativePasswordInput)
		if input.IP != "192.0.2.1" || input.UserAgent != "native-test" || input.Audience != "orders" || input.Scope[0] != "orders.read" {
			t.Fatal(input.Audience, input.IP)
		}
	}
	s := &nativeContract{}
	body := `{"challenge":"native-challenge","binding":"native-binding","code":"recovery-code","recovery":true}`
	w := nativeRequest(New(nativeContractHandlers(s)), "POST", "/native/mfa/complete", body, nil)
	input := s.input.(mfaservice.CompleteLoginInput)
	if w.Code != 200 || !input.Recovery || input.Token != "native-challenge" || input.Binding != "native-binding" || input.IP != "192.0.2.1" {
		t.Fatal(w.Code, input.Recovery)
	}
}

func TestNativeSafeErrors(t *testing.T) {
	for _, tc := range []struct {
		err         error
		status      int
		code, retry string
	}{
		{tokendomain.ErrRateLimited, 429, "rate_limited", "60"},
		{tokendomain.ErrRefreshEarly, 429, "refresh_too_early", "30"},
		{tokendomain.ErrRefreshLimit, 401, "login_required", ""},
		{tokendomain.ErrInvalidRefresh, 401, "invalid_refresh", ""},
		{settingsdomain.ErrMethodDisabled, 404, "method_disabled", ""},
		{settingsdomain.ErrPolicyUnavailable, 503, "temporarily_unavailable", "1"},
		{errors.New("synthetic-secret private SQL error"), 503, "temporarily_unavailable", "1"},
	} {
		s := &nativeContract{err: tc.err}
		w := nativeRequest(New(nativeContractHandlers(s)), "POST", "/token/refresh", nativeRequests[6].body, nil)
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.code) || strings.Contains(w.Body.String(), "synthetic-secret") || w.Header().Get("Retry-After") != tc.retry || w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 {
			t.Fatal(w.Code, w.Body.String(), w.Header())
		}
	}
}
