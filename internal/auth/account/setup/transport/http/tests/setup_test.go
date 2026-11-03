package accountsetuphttp_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	accountsetup "github.com/Inforberi/financial-intelligence/internal/auth/account/setup/service"
	accountsetuphttp "github.com/Inforberi/financial-intelligence/internal/auth/account/setup/transport/http"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type setupPolicyStub struct {
	input accountsetup.SetupStartInput
	err   error
}

func (s *setupPolicyStub) Start(_ context.Context, input accountsetup.SetupStartInput) (*accountsetup.SetupStarted, error) {
	s.input = input
	return &accountsetup.SetupStarted{Token: "pending", ExpiresAt: time.Now().Add(time.Minute)}, s.err
}

func (*setupPolicyStub) Complete(context.Context, accountsetup.SetupCompleteInput) (*accountsetup.SetupCompleted, error) {
	return &accountsetup.SetupCompleted{RecoveryCodes: []string{}}, nil
}

func TestSetupPolicyHTTP(t *testing.T) {
	s := &setupPolicyStub{}
	h := accountsetuphttp.NewSetup(s, zap.NewNop())
	r := httptest.NewRequest("POST", "/api/v1/setup/start", strings.NewReader(`{"email":"owner@example.test","password":"Validpass1","mfaMode":"optional"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Setup-Token", "operator-proof")
	w := httptest.NewRecorder()
	h.Start(w, r)
	if w.Code != 202 || s.input.MFAMode != settingsdomain.MFAOptional || s.input.OperatorSecret != "operator-proof" {
		t.Fatal("lost setup choice/proof", w.Code, w.Body.String())
	}
	var response map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if _, ok := response["secret"]; ok {
		t.Fatal("optional response contains factor")
	}
	if _, ok := response["uri"]; ok {
		t.Fatal("optional response contains factor URI")
	}
	if w.Header().Get("Cache-Control") != "no-store" || len(w.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("setup leaked session or cacheable secrets")
	}
	s.err = settingsdomain.ErrInvalidMFAPolicy
	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/api/v1/setup/start", strings.NewReader(`{"mfaMode":"invalid"}`))
	r.Header.Set("Content-Type", "application/json")
	h.Start(w, r)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_mfa_policy") {
		t.Fatal("unmapped mode error", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/api/v1/setup/complete", strings.NewReader(`{"token":"pending","emailCode":"12345678","mfaMode":"optional"}`))
	r.Header.Set("Content-Type", "application/json")
	h.Complete(w, r)
	if w.Code != 400 {
		t.Fatal("completion accepted client-supplied mode", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invalid_json") {
		t.Fatal(w.Body.String())
	}
}
