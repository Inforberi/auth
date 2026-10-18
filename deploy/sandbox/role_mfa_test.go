package sandbox_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func checkRoleMFA(t *testing.T, admin, api *http.Client, consumer *authjwt.Consumer, suffix string) {
	t.Helper()
	account := activateAdminInvitation(t, admin, api, "mfa-"+suffix)
	var role adminRole
	definition := map[string]any{"key": "sandbox_mfa_" + suffix, "name": "Required MFA acceptance", "permissions": []string{"accounts.users.read"}}
	request(t, admin, "POST", "/api/v1/admin/roles", definition, &role, 201, "Origin", sandboxURL)
	path := "/api/v1/admin/roles/" + role.ID
	assignment := "/api/v1/admin/users/" + account.ID + "/roles/" + role.ID
	card := readAdminUser(t, admin, account.ID)
	request(t, admin, "POST", assignment, assignmentBody(role, card), nil, 200, "Origin", sandboxURL)
	t.Cleanup(func() {
		current := readAdminUser(t, admin, account.ID)
		for _, assigned := range current.Roles {
			if assigned.ID == role.ID {
				request(t, admin, "DELETE", assignment, assignmentBody(role, current), nil, 200, "Origin", sandboxURL)
			}
		}
	})
	user := loginAdminTestUser(t, account)
	old := adminReadToken(t, user)
	consume(t, consumer, old.AccessToken, "accounts.users.read", 204)
	var native tokenResponse
	credentials := map[string]any{"email": account.Email, "password": adminTestPassword, "audience": "sandbox-strict", "scope": []string{"accounts.users.read"}}
	request(t, api, "POST", "/api/v1/auth/native/password/login", credentials, &native, 200)
	if native.AccessToken == "" || native.RefreshToken == "" {
		t.Fatal("missing pre-policy native credentials")
	}
	update := roleUpdate(role, role.Permissions)
	update["mfaRequired"] = true
	request(t, admin, "POST", path, update, &role, 200, "Origin", sandboxURL)
	if !role.MFARequired {
		t.Fatal("role did not enable required MFA")
	}
	assertUnexpired(t, old, native)
	request(t, user, "GET", "/api/v1/auth/me", nil, nil, 401)
	consume(t, consumer, old.AccessToken, "accounts.users.read", 401)
	consume(t, consumer, native.AccessToken, "accounts.users.read", 401)
	request(t, api, "POST", "/api/v1/auth/token/refresh", map[string]string{"refreshToken": native.RefreshToken}, nil, 401)
	completeRequiredRoleEnrollment(t, user, api, account)
	var proof securityProofStatus
	request(t, user, "GET", "/api/v1/auth/mfa/status", nil, &proof, 200)
	if !proof.TOTPEnabled || !proof.RequiredByRole || proof.DisableAllowedByPolicy {
		t.Fatal("required-MFA status does not reflect current role policy")
	}
	// Public login does not establish the separate sensitive-action password proof.
	request(t, user, "POST", "/api/v1/auth/reauthenticate/password", map[string]string{"password": adminTestPassword}, nil, 200, "Origin", sandboxURL)
	expectAdminError(t, user, "DELETE", "/api/v1/auth/mfa/totp", nil, 403, "mfa_required_by_policy")
	consume(t, consumer, adminReadToken(t, user).AccessToken, "accounts.users.read", 204)
	update = roleUpdate(role, role.Permissions)
	update["mfaRequired"] = false
	request(t, admin, "POST", path, update, &role, 200, "Origin", sandboxURL)
	request(t, user, "GET", "/api/v1/auth/mfa/status", nil, &proof, 200)
	if role.MFARequired || proof.RequiredByRole || !proof.TOTPEnabled || !proof.DisableAllowedByPolicy {
		t.Fatal("relaxing role policy removed the factor or left the policy required")
	}
	// Enrollment, replay checks and policy denial share the five-operations/minute budget.
	t.Log("waiting one real MFA budget window before removing the synthetic factor")
	waitSecurityUntil(t, time.Now().Add(61*time.Second))
	request(t, user, "DELETE", "/api/v1/auth/mfa/totp", nil, nil, 200, "Origin", sandboxURL)
	request(t, user, "GET", "/api/v1/auth/me", nil, nil, 401)
	t.Logf("role MFA enforced; test factor removed, synthetic user retained: %s", account.ID)
}

func completeRequiredRoleEnrollment(t *testing.T, user, api *http.Client, account adminAccount) {
	t.Helper()
	var challenge struct{ Challenge, Status string }
	credentials := map[string]string{"email": account.Email, "password": adminTestPassword}
	request(t, user, "POST", "/api/v1/auth/login/email", credentials, &challenge, 202, "Origin", sandboxURL)
	if challenge.Challenge == "" || challenge.Status != "mfa_enrollment_required" {
		t.Fatal("password login bypassed required enrollment")
	}
	request(t, user, "GET", "/api/v1/auth/me", nil, nil, 401)
	request(t, user, "POST", "/api/v1/auth/token/exchange", map[string]any{"audience": "sandbox-strict", "scope": []string{"accounts.users.read"}}, nil, 401, "Origin", sandboxURL)
	input := map[string]string{"challenge": challenge.Challenge}
	expectAdminError(t, api, "POST", "/api/v1/auth/mfa/login/enrollment", input, 400, "invalid_mfa")
	var enrollment struct{ Token, Secret string }
	assertNoLifecycleSession(t, request(t, user, "POST", "/api/v1/auth/mfa/login/enrollment", input, &enrollment, 200, "Origin", sandboxURL))
	if enrollment.Token == "" || enrollment.Secret == "" {
		t.Fatal("missing limited enrollment proof")
	}
	code, err := totp.GenerateCode(enrollment.Secret, time.Now())
	if err != nil {
		t.Fatal("invalid synthetic enrollment secret")
	}
	confirm := map[string]string{"challenge": challenge.Challenge, "token": enrollment.Token, "code": code}
	var recovery struct{ Codes []string }
	request(t, user, "POST", "/api/v1/auth/mfa/login/enrollment/confirm", confirm, &recovery, 200, "Origin", sandboxURL)
	if len(recovery.Codes) == 0 {
		t.Fatal("enrollment did not return one-time recovery material")
	}
	// Confirmation may clear binding cookies, but must never establish a session.
	request(t, user, "GET", "/api/v1/auth/me", nil, nil, 401)
	expectAdminError(t, user, "POST", "/api/v1/auth/mfa/login/enrollment/confirm", confirm, 400, "invalid_mfa")
	request(t, user, "POST", "/api/v1/auth/login/email", credentials, &challenge, 202, "Origin", sandboxURL)
	if challenge.Status != "mfa_required" {
		t.Fatal("enrolled account did not require a second factor")
	}
	waitSecurityUntil(t, time.Now().Truncate(30*time.Second).Add(31*time.Second))
	code, err = totp.GenerateCode(enrollment.Secret, time.Now())
	if err != nil {
		t.Fatal("cannot generate synthetic login TOTP")
	}
	request(t, user, "POST", "/api/v1/auth/mfa/login/complete", map[string]string{"challenge": challenge.Challenge, "code": code}, nil, 200, "Origin", sandboxURL)
	request(t, user, "GET", "/api/v1/auth/me", nil, nil, 200)
}
