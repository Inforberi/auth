package sandbox_test

import (
	"net/http"
	"testing"
	"time"
)

type securityProofStatus struct {
	TOTPEnabled            bool `json:"totpEnabled"`
	RequiredByRole         bool `json:"requiredByRole"`
	DisableAllowedByPolicy bool `json:"disableAllowedByPolicy"`
	FreshPrimaryProof      bool `json:"freshPrimaryProof"`
	FreshMFAProof          bool `json:"freshMfaProof"`
}

func checkFreshAuthExpiry(t *testing.T, admin *http.Client, staleAfter time.Time, suffix string) {
	t.Helper()
	var proof securityProofStatus
	request(t, admin, "GET", "/api/v1/auth/mfa/status", nil, &proof, 200)
	if !proof.FreshPrimaryProof || !proof.FreshMFAProof {
		t.Fatal("admin proofs are not fresh before the deadline")
	}
	definition := map[string]any{"key": "sandbox_fresh_" + suffix, "name": "Freshness acceptance", "permissions": []string{"accounts.users.read"}}
	var role adminRole
	assertNoLifecycleSession(t, request(t, admin, "POST", "/api/v1/admin/roles", definition, &role, 201, "Origin", sandboxURL))
	if role.ID == "" {
		t.Fatal("fresh mutation did not create the test role")
	}
	t.Log("waiting past the real five-minute proof deadline without renewing it")
	waitSecurityUntil(t, staleAfter)
	request(t, admin, "GET", "/api/v1/auth/me", nil, nil, 200)
	request(t, admin, "GET", "/api/v1/admin/roles/"+role.ID, nil, nil, 200)
	request(t, admin, "GET", "/api/v1/auth/mfa/status", nil, &proof, 200)
	if proof.FreshPrimaryProof || proof.FreshMFAProof {
		t.Fatal("ordinary reads extended authentication freshness")
	}
	update := roleUpdate(role, []string{"accounts.users.read"})
	update["name"] = "Freshness renewed"
	expectAdminError(t, admin, "POST", "/api/v1/admin/roles/"+role.ID, update, 403, "fresh_auth_required")
	request(t, admin, "POST", "/api/v1/auth/reauthenticate/password", map[string]string{"password": "Sandbox-Admin-2026!"}, nil, 200, "Origin", sandboxURL)
	request(t, admin, "GET", "/api/v1/auth/mfa/status", nil, &proof, 200)
	if !proof.FreshPrimaryProof || proof.FreshMFAProof {
		t.Fatal("password-only reauthentication refreshed MFA")
	}
	expectAdminError(t, admin, "POST", "/api/v1/admin/roles/"+role.ID, update, 403, "fresh_auth_required")
	request(t, admin, "POST", "/api/v1/auth/mfa/step-up", map[string]string{"code": adminCode(t)}, nil, 200, "Origin", sandboxURL)
	var renewed adminRole
	assertNoLifecycleSession(t, request(t, admin, "POST", "/api/v1/admin/roles/"+role.ID, update, &renewed, 200, "Origin", sandboxURL))
	if renewed.ID != role.ID || renewed.Version <= role.Version {
		t.Fatal("fresh password and MFA did not restore the administrative mutation")
	}
	t.Log("reads survive expiry; mutations need renewed password AND MFA")
}
