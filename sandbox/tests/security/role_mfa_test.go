package sandbox_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
	testsupport "github.com/Inforberi/financial-intelligence/sandbox/internal/testsupport"
)

func checkRoleMFA(t *testing.T, admin, api *http.Client, consumer *authjwt.Consumer, suffix string) {
	t.Helper()
	account := testsupport.ActivateAdminInvitation(t, admin, api, "mfa-"+suffix)
	var role testsupport.AdminRole
	definition := map[string]any{"key": "sandbox_mfa_" + suffix, "name": "Required MFA acceptance", "permissions": []string{"accounts.users.read"}}
	testsupport.Request(t, admin, "POST", "/api/v1/admin/roles", definition, &role, 201, "Origin", testsupport.SandboxURL)
	path := "/api/v1/admin/roles/" + role.ID
	assignment := "/api/v1/admin/users/" + account.ID + "/roles/" + role.ID
	card := testsupport.ReadAdminUser(t, admin, account.ID)
	testsupport.Request(t, admin, "POST", assignment, testsupport.AssignmentBody(role, card), nil, 200, "Origin", testsupport.SandboxURL)
	t.Cleanup(func() {
		current := testsupport.ReadAdminUser(t, admin, account.ID)
		for _, assigned := range current.Roles {
			if assigned.ID == role.ID {
				testsupport.Request(t, admin, "DELETE", assignment, testsupport.AssignmentBody(role, current), nil, 200, "Origin", testsupport.SandboxURL)
			}
		}
	})
	user := testsupport.LoginAdminTestUser(t, account)
	old := testsupport.AdminReadToken(t, user)
	testsupport.Consume(t, consumer, old.AccessToken, "accounts.users.read", 204)
	var native testsupport.TokenResponse
	credentials := map[string]any{"email": account.Email, "password": testsupport.AdminTestPassword, "audience": "sandbox-strict", "scope": []string{"accounts.users.read"}}
	testsupport.Request(t, api, "POST", "/api/v1/auth/native/password/login", credentials, &native, 200)
	if native.AccessToken == "" || native.RefreshToken == "" {
		t.Fatal("missing pre-policy native credentials")
	}
	update := testsupport.RoleUpdate(role, role.Permissions)
	update["mfaRequired"] = true
	testsupport.Request(t, admin, "POST", path, update, &role, 200, "Origin", testsupport.SandboxURL)
	if !role.MFARequired {
		t.Fatal("role did not enable required MFA")
	}
	testsupport.AssertUnexpired(t, old, native)
	testsupport.Request(t, user, "GET", "/api/v1/auth/me", nil, nil, 401)
	testsupport.Consume(t, consumer, old.AccessToken, "accounts.users.read", 401)
	testsupport.Consume(t, consumer, native.AccessToken, "accounts.users.read", 401)
	testsupport.Request(t, api, "POST", "/api/v1/auth/token/refresh", map[string]string{"refreshToken": native.RefreshToken}, nil, 401)
	completeRequiredRoleEnrollment(t, user, api, account)
	var proof securityProofStatus
	testsupport.Request(t, user, "GET", "/api/v1/auth/mfa/status", nil, &proof, 200)
	if !proof.TOTPEnabled || !proof.RequiredByRole || proof.DisableAllowedByPolicy {
		t.Fatal("required-MFA status does not reflect current role policy")
	}
	// Public login does not establish the separate sensitive-action password proof.
	testsupport.Request(t, user, "POST", "/api/v1/auth/reauthenticate/password", map[string]string{"password": testsupport.AdminTestPassword}, nil, 200, "Origin", testsupport.SandboxURL)
	testsupport.ExpectAdminError(t, user, "DELETE", "/api/v1/auth/mfa/totp", nil, 403, "mfa_required_by_policy")
	testsupport.Consume(t, consumer, testsupport.AdminReadToken(t, user).AccessToken, "accounts.users.read", 204)
	update = testsupport.RoleUpdate(role, role.Permissions)
	update["mfaRequired"] = false
	testsupport.Request(t, admin, "POST", path, update, &role, 200, "Origin", testsupport.SandboxURL)
	testsupport.Request(t, user, "GET", "/api/v1/auth/mfa/status", nil, &proof, 200)
	if role.MFARequired || proof.RequiredByRole || !proof.TOTPEnabled || !proof.DisableAllowedByPolicy {
		t.Fatal("relaxing role policy removed the factor or left the policy required")
	}
	// Enrollment, replay checks and policy denial share the five-operations/minute budget.
	t.Log("waiting one real MFA budget window before removing the synthetic factor")
	testsupport.WaitSecurityUntil(t, time.Now().Add(61*time.Second))
	testsupport.Request(t, user, "DELETE", "/api/v1/auth/mfa/totp", nil, nil, 200, "Origin", testsupport.SandboxURL)
	testsupport.Request(t, user, "GET", "/api/v1/auth/me", nil, nil, 401)
	t.Logf("role MFA enforced; test factor removed, synthetic user retained: %s", account.ID)
}

func completeRequiredRoleEnrollment(t *testing.T, user, api *http.Client, account testsupport.AdminAccount) {
	t.Helper()
	var challenge struct{ Challenge, Status string }
	credentials := map[string]string{"email": account.Email, "password": testsupport.AdminTestPassword}
	testsupport.Request(t, user, "POST", "/api/v1/auth/login/email", credentials, &challenge, 202, "Origin", testsupport.SandboxURL)
	if challenge.Challenge == "" || challenge.Status != "mfa_enrollment_required" {
		t.Fatal("password login bypassed required enrollment")
	}
	testsupport.Request(t, user, "GET", "/api/v1/auth/me", nil, nil, 401)
	testsupport.Request(t, user, "POST", "/api/v1/auth/token/exchange", map[string]any{"audience": "sandbox-strict", "scope": []string{"accounts.users.read"}}, nil, 401, "Origin", testsupport.SandboxURL)
	input := map[string]string{"challenge": challenge.Challenge}
	testsupport.ExpectAdminError(t, api, "POST", "/api/v1/auth/mfa/login/enrollment", input, 400, "invalid_mfa")
	var enrollment struct{ Token, Secret string }
	testsupport.AssertNoLifecycleSession(t, testsupport.Request(t, user, "POST", "/api/v1/auth/mfa/login/enrollment", input, &enrollment, 200, "Origin", testsupport.SandboxURL))
	if enrollment.Token == "" || enrollment.Secret == "" {
		t.Fatal("missing limited enrollment proof")
	}
	code, err := totp.GenerateCode(enrollment.Secret, time.Now())
	if err != nil {
		t.Fatal("invalid synthetic enrollment secret")
	}
	confirm := map[string]string{"challenge": challenge.Challenge, "token": enrollment.Token, "code": code}
	var recovery struct{ Codes []string }
	testsupport.Request(t, user, "POST", "/api/v1/auth/mfa/login/enrollment/confirm", confirm, &recovery, 200, "Origin", testsupport.SandboxURL)
	if len(recovery.Codes) == 0 {
		t.Fatal("enrollment did not return one-time recovery material")
	}
	// Confirmation may clear binding cookies, but must never establish a session.
	testsupport.Request(t, user, "GET", "/api/v1/auth/me", nil, nil, 401)
	testsupport.ExpectAdminError(t, user, "POST", "/api/v1/auth/mfa/login/enrollment/confirm", confirm, 400, "invalid_mfa")
	testsupport.Request(t, user, "POST", "/api/v1/auth/login/email", credentials, &challenge, 202, "Origin", testsupport.SandboxURL)
	if challenge.Status != "mfa_required" {
		t.Fatal("enrolled account did not require a second factor")
	}
	testsupport.WaitSecurityUntil(t, time.Now().Truncate(30*time.Second).Add(31*time.Second))
	code, err = totp.GenerateCode(enrollment.Secret, time.Now())
	if err != nil {
		t.Fatal("cannot generate synthetic login TOTP")
	}
	testsupport.Request(t, user, "POST", "/api/v1/auth/mfa/login/complete", map[string]string{"challenge": challenge.Challenge, "code": code}, nil, 200, "Origin", testsupport.SandboxURL)
	testsupport.Request(t, user, "GET", "/api/v1/auth/me", nil, nil, 200)
}
