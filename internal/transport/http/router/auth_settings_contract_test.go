package router

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
)

var availableSettingsMethods = settingsdomain.PublicMethods{Password: true, EmailOTP: true, Google: true, Telegram: true}

const settingsBody = `{"expectedVersion":7,"policy":{"methods":{"password":false,"emailOtp":false,"google":false,"telegram":false},"registration":{"enabled":false,"google":false,"telegram":false},"passwordEmailVerification":"required","tokenIssuance":{"sessionExchange":false,"native":false}}}`

type contractAuthSettings struct {
	calls int
	actor accessservice.Principal
	input settingsservice.UpdateInput
	err   error
}

func (s *contractAuthSettings) Read(_ context.Context, actor accessservice.Principal) (settingsdomain.Snapshot, error) {
	s.calls++
	s.actor = actor
	return settingsdomain.Snapshot{Version: 7, Policy: settingsdomain.Policy{PasswordEmailVerification: settingsdomain.VerificationRequired}}, s.err
}

func (s *contractAuthSettings) Update(_ context.Context, input settingsservice.UpdateInput) (settingsdomain.Snapshot, error) {
	s.calls++
	s.input = input
	s.actor = input.Actor
	return settingsdomain.Snapshot{Version: 8, Policy: input.Policy}, s.err
}

func TestAuthSettingsRouteGuards(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		for _, tc := range []struct {
			cookie, origin string
			status         int
		}{
			{"", "https://localhost:8443", 401},
			{validCookieToken, "https://evil.example", 403},
			{validCookieToken, "https://localhost:8443", 200},
		} {
			h := contractHandlers("prod")
			svc := &contractAuthSettings{}
			h.AuthSettings = settingshttp.NewWithTokenDeployment(svc, availableSettingsMethods, settingsdomain.TokenDeployment{Enabled: true, Issuer: "https://auth.example", AccessTTLSeconds: 120}, zap.NewNop())
			req := httptest.NewRequest(method, "/api/v1/admin/auth/settings", strings.NewReader(settingsBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", tc.origin)
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "__Host-session", Value: tc.cookie})
			}
			w := httptest.NewRecorder()
			New(h).ServeHTTP(w, req)
			if w.Code != tc.status || w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 {
				t.Fatal(method, w.Code, w.Body.String())
			}
			if tc.status != 200 {
				if strings.Contains(w.Body.String(), "tokenProfiles") {
					t.Fatal("metadata exposed before authorization")
				}
				if svc.calls != 0 {
					t.Fatal("untrusted request reached settings service")
				}
				continue
			}
			if svc.calls != 1 || svc.actor.UserID == "" || svc.actor.TokenHash == "" {
				t.Fatal("missing trusted actor")
			}
			var result settingshttp.SettingsResponse
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || !result.AvailableMethods.Google {
				t.Fatal(result, err)
			}
			if !result.TokenProfiles.JWTEnabled || result.TokenProfiles.BrowserAdminTransport != "cookie" || result.TokenProfiles.Scope != "instance" {
				t.Fatal(result.TokenProfiles)
			}
			if method == "POST" && (result.Version != 8 || svc.input.ExpectedVersion != 7 || svc.input.Policy.Methods.Password) {
				t.Fatal("explicit false/full replacement lost", result, svc.input)
			}
		}
	}
}

func TestAuthSettingsMutationRequiresMFA(t *testing.T) {
	h := contractHandlers("prod")
	h.Config.MFA.Enabled = false
	router := New(h)
	for _, method := range []string{"GET", "POST"} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(method, "/api/v1/admin/auth/settings", nil))
		if method == "GET" && w.Code != 401 {
			t.Fatal("read route disappeared", w.Code)
		}
		if method == "POST" && w.Code != 405 {
			t.Fatal("MFA-disabled update exposed", w.Code)
		}
	}
}

func TestAuthSettingsSwagger(t *testing.T) {
	doc := readAPI(t)
	profiles := doc.Definitions["auth_settings_http.TokenProfilesResponse"]
	fields := []string{"managedBy", "scope", "changesRequireRollout", "browserAdminTransport", "jwtEnabled", "sessionExchangeEnabled", "nativeEnabled", "introspectionEnabled", "issuer", "accessTtlSeconds", "resources"}
	if len(profiles.Properties) != len(fields) {
		t.Fatal("unexpected deployment fields", profiles)
	}
	for _, field := range fields {
		if _, ok := profiles.Properties[field]; !ok {
			t.Fatal("missing deployment metadata", field)
		}
	}
	for name, fields := range map[string][]string{
		"UpdateRequest":        {"expectedVersion", "policy"},
		"PolicyRequest":        {"methods", "registration", "passwordEmailVerification", "tokenIssuance"},
		"TokenIssuanceRequest": {"sessionExchange", "native"},
		"MethodsRequest":       {"password", "emailOtp", "google", "telegram"},
		"RegistrationRequest":  {"enabled", "google", "telegram"},
	} {
		schema := doc.Definitions["auth_settings_http."+name]
		if len(schema.Properties) != len(fields) || len(schema.Required) != len(fields) {
			t.Fatal("incomplete settings schema", name, schema)
		}
		for _, field := range fields {
			if _, ok := schema.Properties[field]; !ok || !slices.Contains(schema.Required, field) {
				t.Fatal("missing required field", name, field)
			}
		}
	}
	for _, method := range []string{"get", "post"} {
		operation := doc.Paths["/api/v1/admin/auth/settings"][method]
		if operation.Responses["200"].Schema.Ref != "#/definitions/auth_settings_http.SettingsResponse" {
			t.Fatal("wrong settings response", method)
		}
	}
	response := doc.Definitions["auth_settings_http.SettingsResponse"]
	if len(response.Properties) != 4 || response.Properties["availableMethods"].Ref != "#/definitions/auth_settings_http.MethodsResponse" || response.Properties["tokenProfiles"].Ref != "#/definitions/auth_settings_http.TokenProfilesResponse" {
		t.Fatal("unexpected settings response fields", response)
	}
}

func TestTokenMetadataDoesNotAcceptBearerAsAdminSession(t *testing.T) {
	h := contractHandlers("prod")
	svc := &contractAuthSettings{}
	h.AuthSettings = settingshttp.NewWithTokenDeployment(svc, availableSettingsMethods, settingsdomain.TokenDeployment{Enabled: true}, zap.NewNop())
	r := httptest.NewRequest("GET", "/api/v1/admin/auth/settings", nil)
	r.Header.Set("Origin", "https://localhost:8443")
	r.Header.Set("Authorization", "Bearer synthetic-access-token")
	w := httptest.NewRecorder()
	New(h).ServeHTTP(w, r)
	if w.Code != 401 || svc.calls != 0 || strings.Contains(w.Body.String(), "tokenProfiles") {
		t.Fatal(w.Code, w.Body.String())
	}
}
