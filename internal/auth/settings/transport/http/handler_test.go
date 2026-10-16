package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

const completePolicy = `{"expectedVersion":3,"policy":{"methods":{"password":false,"emailOtp":false,"google":false,"telegram":false},"registration":{"enabled":false,"google":false,"telegram":false},"passwordEmailVerification":"required"}}`

type captureSettings struct {
	calls int
	input service.UpdateInput
	err   error
}

func (s *captureSettings) Read(_ context.Context, actor accessservice.Principal) (domain.Snapshot, error) {
	s.calls++
	s.input.Actor = actor
	return domain.Snapshot{Version: 3, Policy: domain.Policy{PasswordEmailVerification: domain.VerificationRequired}}, s.err
}

func (s *captureSettings) Update(_ context.Context, input service.UpdateInput) (domain.Snapshot, error) {
	s.calls++
	s.input = input
	return domain.Snapshot{Version: 4, Policy: input.Policy}, s.err
}

var settingsActor = accessservice.Principal{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64)}

func settingsRequest(body string) *http.Request {
	r := httptest.NewRequest("POST", "/api/v1/admin/auth/settings", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r.WithContext(sessionhttp.SetAuthContext(r.Context(), sessionhttp.Auth{UserID: settingsActor.UserID, TokenHash: settingsActor.TokenHash}))
}

func TestSettingsFullReplacement(t *testing.T) {
	svc := &captureSettings{}
	h := New(svc, domain.PublicMethods{Password: true}, zap.NewNop())
	w := httptest.NewRecorder()
	h.Update(w, settingsRequest(completePolicy))
	if w.Code != 200 || svc.calls != 1 || svc.input.Actor != settingsActor || svc.input.ExpectedVersion != 3 || svc.input.Policy.Methods != (domain.PublicMethods{}) {
		t.Fatal(w.Code, w.Body.String(), svc.input)
	}
	var result SettingsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Version != 4 || result.Policy.PasswordEmailVerification != domain.VerificationRequired || !result.AvailableMethods.Password {
		t.Fatal(result, err)
	}
	if w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 {
		t.Fatal("cache/session side effect")
	}
}

func TestSettingsRejectsIncompleteAndUnknownFields(t *testing.T) {
	bodies := []string{`{`, `{}`, `null`, `{"policy":null}`, `{"policy":{"methods":{},"registration":{}}}`, completePolicy + ` {}`, strings.Replace(completePolicy, `"password":false`, `"password":null`, 1), strings.Replace(completePolicy, `"password":false,`, ``, 1), strings.Replace(completePolicy, `"password":false`, `"password":"false"`, 1), strings.Replace(completePolicy, `"methods":{`, `"methods":{"clientSecret":"secret",`, 1), strings.Replace(completePolicy, `"expectedVersion":3`, `"actorId":"forged","expectedVersion":3`, 1)}
	for _, body := range bodies {
		svc := &captureSettings{}
		w := httptest.NewRecorder()
		New(svc, domain.PublicMethods{}, zap.NewNop()).Update(w, settingsRequest(body))
		if w.Code != 400 || svc.calls != 0 {
			t.Fatal(body, w.Code, w.Body.String())
		}
	}
	// Presence is transport's responsibility; enum/version validation belongs to service.
	svc := &captureSettings{}
	w := httptest.NewRecorder()
	New(svc, domain.PublicMethods{}, zap.NewNop()).Update(w, settingsRequest(strings.Replace(completePolicy, `"required"`, `"unknown"`, 1)))
	if svc.calls != 1 || svc.input.Policy.PasswordEmailVerification != "unknown" {
		t.Fatal("HTTP duplicated domain validation")
	}
}

func TestSettingsErrorsAreSafe(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{domain.ErrInvalidPolicy, 400, "invalid_auth_policy"},
		{domain.ErrPolicyConflict, 409, "auth_policy_conflict"},
		{domain.ErrMethodNotReady, 409, "auth_method_not_ready"},
		{accessdomain.ErrForbidden, 403, "forbidden"},
		{accessdomain.ErrFreshAuthRequired, 403, "fresh_auth_required"},
		{fmt.Errorf("private DSN token"), 503, "temporarily_unavailable"},
	} {
		core, logs := observer.New(zap.DebugLevel)
		svc := &captureSettings{err: fmt.Errorf("%w: private dependency detail", tc.err)}
		h := New(svc, domain.PublicMethods{}, zap.New(core))
		for _, handler := range []http.HandlerFunc{h.Read, h.Update} {
			w := httptest.NewRecorder()
			handler(w, settingsRequest(completePolicy))
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.code) {
				t.Fatal(w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "private") || strings.Contains(fmt.Sprint(logs.All()), "private") {
				t.Fatal("private error leaked")
			}
		}
	}
}

func TestSettingsRequiresTrustedContext(t *testing.T) {
	svc := &captureSettings{}
	h := New(svc, domain.PublicMethods{}, zap.NewNop())
	for _, handler := range []http.HandlerFunc{h.Read, h.Update} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest("POST", "/", strings.NewReader(completePolicy)))
		if w.Code != 401 || svc.calls != 0 {
			t.Fatal("missing principal accepted", w.Code)
		}
	}
}
