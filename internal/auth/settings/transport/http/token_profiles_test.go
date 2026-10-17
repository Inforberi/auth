package http

import (
	"encoding/json"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestTokenProfilesAreReadOnlyInstanceMetadata(t *testing.T) {
	resources := []domain.TokenResource{{Audience: "reports", Mode: "local", Permissions: []string{"reports.read"}}, {Audience: "orders", Mode: "strict", Permissions: []string{"orders.write", "orders.read"}}}
	deployment := domain.TokenDeployment{Enabled: true, NativeEnabled: true, IntrospectionEnabled: true, Issuer: "https://auth.example", AccessTTLSeconds: 120, Resources: resources}
	svc := &captureSettings{}
	h := NewWithTokenDeployment(svc, domain.PublicMethods{Password: true}, deployment, zap.NewNop())
	resources[1].Permissions[0] = "injected.permission"
	resources[0].Audience = "injected-audience"
	for _, handler := range []func(*httptest.ResponseRecorder){
		func(w *httptest.ResponseRecorder) { h.Read(w, settingsRequest("")) },
		func(w *httptest.ResponseRecorder) { h.Update(w, settingsRequest(completePolicy)) },
	} {
		before := svc.calls
		w := httptest.NewRecorder()
		handler(w)
		var result SettingsResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || svc.calls != before+1 {
			t.Fatal(w.Code, w.Body.String())
		}
		profiles := result.TokenProfiles
		if profiles.ManagedBy != "deployment" || profiles.Scope != "instance" || !profiles.ChangesRequireRollout || profiles.BrowserAdminTransport != "cookie" || !profiles.JWTEnabled || !profiles.SessionExchangeEnabled || !profiles.NativeEnabled || !profiles.IntrospectionEnabled || profiles.Issuer != deployment.Issuer || profiles.AccessTTLSeconds != 120 {
			t.Fatal(profiles)
		}
		if len(profiles.Resources) != 2 || profiles.Resources[0].Audience != "orders" || profiles.Resources[0].Revocation != "online" || profiles.Resources[1].Audience != "reports" || profiles.Resources[1].Revocation != "token_expiry" || !slices.Equal(profiles.Resources[0].Permissions, []string{"orders.read", "orders.write"}) {
			t.Fatal("mutable/incorrect resources", profiles.Resources)
		}
		if w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 {
			t.Fatal("response side effects")
		}
	}
	for _, body := range []string{
		strings.Replace(completePolicy, `"expectedVersion":3`, `"tokenProfiles":{"nativeEnabled":false},"expectedVersion":3`, 1),
		strings.Replace(completePolicy, `"policy":{`, `"policy":{"tokenProfiles":{"mode":"local"},`, 1),
		strings.Replace(completePolicy, `"policy":{`, `"policy":{"JWT_ENABLED":false,`, 1),
	} {
		before := svc.calls
		w := httptest.NewRecorder()
		h.Update(w, settingsRequest(body))
		if w.Code != 400 || svc.calls != before {
			t.Fatal("deployment mutation accepted", w.Code, w.Body.String())
		}
	}
}

func TestTokenProfilesDisabledAndProtected(t *testing.T) {
	svc := &captureSettings{}
	deployment := domain.TokenDeployment{Issuer: "not-loaded", AccessTTLSeconds: 120, NativeEnabled: true, IntrospectionEnabled: true, Resources: []domain.TokenResource{{Audience: "not-loaded"}}}
	h := NewWithTokenDeployment(svc, domain.PublicMethods{}, deployment, zap.NewNop())
	w := httptest.NewRecorder()
	h.Read(w, settingsRequest(""))
	var result SettingsResponse
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.TokenProfiles.JWTEnabled || result.TokenProfiles.NativeEnabled || result.TokenProfiles.IntrospectionEnabled || len(result.TokenProfiles.Resources) != 0 || result.TokenProfiles.Resources == nil || strings.Contains(w.Body.String(), "not-loaded") {
		t.Fatal(w.Body.String())
	}
	svc.err = accessdomain.ErrForbidden
	w = httptest.NewRecorder()
	h.Read(w, settingsRequest(""))
	if w.Code != 403 || strings.Contains(w.Body.String(), "tokenProfiles") {
		t.Fatal("unauthorized metadata leak", w.Code, w.Body.String())
	}
}
