package settingshttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
)

func TestPublicMethodsUsePolicyAndAdapters(t *testing.T) {
	policy := domain.Policy{
		Methods:                   domain.PublicMethods{Password: true, Google: true, Telegram: true},
		Registration:              domain.PublicRegistration{Enabled: true, Google: true},
		PasswordEmailVerification: domain.VerificationRequired,
	}
	var loadErr error
	handler := settingshttp.PublicMethods(func(context.Context) (domain.Policy, error) {
		return policy, loadErr
	}, domain.PublicMethods{Password: true, EmailOTP: true, Telegram: true})

	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/methods", nil)
	response := httptest.NewRecorder()
	handler(response, request)
	var result settingshttp.PublicMethodsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("unexpected status or cache policy")
	}
	if result.Login != (settingshttp.MethodsResponse{Password: true, Telegram: true}) ||
		result.Registration != (settingshttp.PublicRegistrationResponse{Password: true}) ||
		!result.PasswordVerificationRequired {
		t.Fatalf("unexpected discovery response: %+v", result)
	}

	loadErr = errors.New("storage unavailable")
	response = httptest.NewRecorder()
	handler(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected status on storage failure: %d", response.Code)
	}
}
