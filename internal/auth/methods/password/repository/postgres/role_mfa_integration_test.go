package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatotp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

func TestRoleMFAPolicySchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	accessExec(t, db, ctx, `CREATE ROLE auth_role_mfa_runtime LOGIN PASSWORD 'synthetic-recovery-only';
		GRANT USAGE ON SCHEMA auth TO auth_role_mfa_runtime;
		GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA auth TO auth_role_mfa_runtime`)
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down"); accessExec(t, db, ctx, `DROP ROLE auth_role_mfa_runtime`) })
	runtime := operatorPool(t, ctx, db, "auth_role_mfa_runtime")
	// A required but unassigned role must also prevent a deployment without MFA.
	accessExec(t, db, ctx, `INSERT INTO auth.roles(key,name,mfa_required) VALUES('future_mfa','Future MFA',true)`)
	if err := mfapostgres.New(runtime).CheckDisabled(ctx); err == nil {
		t.Fatal("disabled MFA accepted a required role")
	}
	accessExec(t, db, ctx, `DELETE FROM auth.roles WHERE key='future_mfa'`)
	actor := accessPrincipal(t, db, ctx)
	accessExec(t, db, ctx, `WITH r AS (INSERT INTO auth.roles(key,name) VALUES('mfa_operator','Operator') RETURNING id),
		p AS (INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,unnest(ARRAY['access.roles.manage','access.assignments.manage','reports.read']) FROM r)
		INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, actor.UserID)
	catalog, err := settings.NewCatalog([]settings.Permission{{Key: "reports.read", Name: "Read reports"}})
	if err != nil {
		t.Fatal(err)
	}
	svc := accessservice.New(accesspostgres.NewWithMFA(runtime, true), catalog)
	role, err := svc.CreateRole(ctx, accessservice.CreateRoleInput{Actor: actor, Key: "mfa_reader", Name: "Reader", Permissions: []accessdomain.PermissionKey{"reports.read"}})
	if err != nil {
		t.Fatal(err)
	}
	f := newStatusFixture(t, db, ctx, "role-mfa")
	if _, err := svc.ChangeAssignment(ctx, accessservice.AssignmentInput{Actor: actor, UserID: f.user, RoleID: role.ID, ExpectedRoleVersion: role.Version, ExpectedAccessVersion: 1, Grant: true}); err != nil {
		t.Fatal(err)
	}
	p := f.params
	p.AuthVersion = 2
	p.TokenHash = tokengenerate.New().Hash("before-mfa-required")
	sessions := sessionpostgres.New(runtime)
	if _, err := sessions.CreateSession(ctx, p); err != nil {
		t.Fatal(err)
	}
	required := true
	input := accessservice.UpdateRoleInput{CreateRoleInput: accessservice.CreateRoleInput{Actor: actor, Key: role.Key, Name: role.Name, Permissions: role.Permissions, MFARequired: &required}, RoleID: role.ID, ExpectedVersion: role.Version}
	if _, err := accesspostgres.New(runtime).UpdateRole(ctx, input); !errors.Is(err, accessdomain.ErrMFANotReady) {
		t.Fatal("policy enabled on unprepared instance", err)
	}
	accessExec(t, db, ctx, `ALTER TABLE auth.access_audit ADD CONSTRAINT reject_role_policy CHECK(event<>'role_updated') NOT VALID`)
	if _, err := svc.UpdateRole(ctx, input); err == nil {
		t.Fatal("audit failure committed role policy")
	}
	if _, err := sessions.FindSession(ctx, p.TokenHash); err != nil {
		t.Fatal("rollback invalidated old session", err)
	}
	accessExec(t, db, ctx, `ALTER TABLE auth.access_audit DROP CONSTRAINT reject_role_policy`)
	role, err = svc.UpdateRole(ctx, input)
	if err != nil || !role.MFARequired {
		t.Fatal("required policy missing", role, err)
	}
	if _, err := sessions.FindSession(ctx, p.TokenHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("old token bypassed new MFA requirement", err)
	}
	if _, err := sessions.CreateSession(ctx, p); !errors.Is(err, sessiondomain.ErrMFARequired) {
		t.Fatal("plain issuance bypassed required role", err)
	}
	if _, err := runtime.Exec(ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,user_agent,ip_address)
		VALUES(repeat('f',64),$1,2,statement_timestamp(),statement_timestamp()+interval '1 hour',statement_timestamp()+interval '2 hours','','')`, f.user); err == nil {
		t.Fatal("direct INSERT bypassed required MFA")
	}
	input.ExpectedVersion = role.Version
	input.MFARequired = nil
	input.Name = "Renamed reader"
	role, err = svc.UpdateRole(ctx, input)
	if err != nil || !role.MFARequired {
		t.Fatal("older client cleared MFA policy", role, err)
	}
	input.ExpectedVersion = 1
	if _, err := svc.UpdateRole(ctx, input); !errors.Is(err, accessdomain.ErrConflict) {
		t.Fatal("stale edit accepted", err)
	}
	checkRequiredRoleLogin(t, db, runtime, ctx, f, role, svc, actor)
	// Issuance that started before tightening cannot inherit the new policy revision on late commit.
	role, err = svc.ReadManagedRole(ctx, actor, role.ID)
	if err != nil {
		t.Fatal(err)
	}
	late, err := runtime.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = late.Rollback(ctx) }()
	lateHash := tokengenerate.New().Hash("late-role-mfa-session")
	if _, err := late.Exec(ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,user_agent,ip_address)
		SELECT $1,id,auth_version,statement_timestamp(),statement_timestamp()+interval '1 hour',statement_timestamp()+interval '2 hours','','' FROM auth.users WHERE id=$2`, lateHash, f.user); err != nil {
		t.Fatal(err)
	}
	input.Name = role.Name
	input.ExpectedVersion = role.Version
	input.MFARequired = &required
	role, err = svc.UpdateRole(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if err := late.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.FindSession(ctx, lateHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("late commit inherited tightened policy", err)
	}
	second, err := svc.CreateRole(ctx, accessservice.CreateRoleInput{Actor: actor, Key: "second_required", Name: "Second required", MFARequired: &required})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ChangeAssignment(ctx, accessservice.AssignmentInput{Actor: actor, UserID: f.user, RoleID: second.ID, ExpectedRoleVersion: second.Version, ExpectedAccessVersion: 2, Grant: true}); err != nil {
		t.Fatal(err)
	}
	optional := false
	input.ExpectedVersion = role.Version
	input.MFARequired = &optional
	if _, err := svc.UpdateRole(ctx, input); err != nil {
		t.Fatal(err)
	}
	var stillRequired bool
	if err := db.QueryRow(ctx, `SELECT auth.role_requires_mfa($1)`, f.user).Scan(&stillRequired); err != nil || !stillRequired {
		t.Fatal("roles did not combine MFA requirements with OR", err)
	}
}

// Primary proof fixtures below exercise SQL/coordination, not external provider validation or SMTP.
func TestRoleMFAOtherPrimaryMethods(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	accessExec(t, db, ctx, `INSERT INTO auth.roles(key,name,mfa_required) VALUES('primary_mfa','Primary MFA',true)`)
	for _, kind := range []string{"google", "telegram", "emailotp"} {
		t.Run(kind, func(t *testing.T) {
			f := newStatusFixture(t, db, ctx, "required-"+kind)
			accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM auth.roles WHERE key='primary_mfa'`, f.user)
			proof := mfaservice.PrimaryProof{UserID: f.user, AuthVersion: 1, VerifiedAt: time.Now().UTC()}
			if kind == "emailotp" {
				proof.Method = "emailotp"
				accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, f.user)
				if err := db.QueryRow(ctx, `SELECT email_id FROM auth.password_credentials WHERE user_id=$1`, f.user).Scan(&proof.Reference); err != nil {
					t.Fatal(err)
				}
			} else {
				proof.Method, proof.Reference, proof.Issuer = "oidc", "primary-"+kind, "https://accounts.google.com"
				if kind == "telegram" {
					proof.Issuer = "https://oauth.telegram.org"
				}
				accessExec(t, db, ctx, `INSERT INTO auth.linked_identities(user_id,issuer,subject) VALUES($1,$2,$3)`, f.user, proof.Issuer, proof.Reference)
				accessExec(t, db, ctx, `DELETE FROM auth.password_credentials WHERE user_id=$1`, f.user)
			}
			cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
			if err != nil {
				t.Fatal(err)
			}
			login, err := mfaservice.NewLogin(mfapostgres.New(db), cipher, mfatotp.Authenticator{}, mfaTestLimit{}, tokengenerate.New(), mfaservice.LoginConfig{
				ChallengeTTL: 5 * time.Minute, SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour, UserLimitPerMinute: 5, IPLimitPerMinute: 10, GlobalLimitPerMinute: 500,
			})
			if err != nil {
				t.Fatal(err)
			}
			coordinator := sessionservice.NewLogin(sessionservice.New(clock.UTCClock{}, f.sessions, tokengenerate.New(), sessionservice.Config{SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour}), login)
			first, err := coordinator.BeginLogin(ctx, proof, "", "")
			if err != nil || first.Challenge == nil || !first.Challenge.EnrollmentRequired || first.RawToken != "" {
				t.Fatal("primary bypassed required MFA", first, err)
			}
			input := mfaservice.LoginEnrollmentInput{Challenge: first.Challenge.Token, Binding: first.Challenge.Binding}
			enrollment, err := login.StartRequiredEnrollment(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			codes, err := login.ConfirmRequiredEnrollment(ctx, mfaservice.ConfirmLoginEnrollmentInput{LoginEnrollmentInput: input, Token: enrollment.Token, Code: mfaCode(t, db, ctx, enrollment.Secret, 0)})
			if err != nil {
				t.Fatal(err)
			}
			proof.AuthVersion = 2
			proof.VerifiedAt = time.Now().UTC()
			second, err := coordinator.BeginLogin(ctx, proof, "", "")
			if err != nil || second.Challenge == nil || second.Challenge.EnrollmentRequired {
				t.Fatal("enrolled primary skipped normal MFA", second, err)
			}
			if _, err := login.Complete(ctx, mfaservice.CompleteLoginInput{Token: second.Challenge.Token, Binding: second.Challenge.Binding, Recovery: true, Code: codes.Codes[0]}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func checkRequiredRoleLogin(t *testing.T, db, runtime *pgxpool.Pool, ctx context.Context, f statusFixture, role accessdomain.Role, access *accessservice.Service, actor accessservice.Principal) {
	t.Helper()
	tokens := tokengenerate.New()
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	repo := mfapostgres.New(runtime)
	login, err := mfaservice.NewLogin(repo, cipher, mfatotp.Authenticator{}, mfaTestLimit{}, tokens, mfaservice.LoginConfig{
		Issuer: "Role MFA test", ChallengeTTL: 5 * time.Minute, SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour,
		UserLimitPerMinute: 5, IPLimitPerMinute: 10, GlobalLimitPerMinute: 500,
	})
	if err != nil {
		t.Fatal(err)
	}
	sessions := sessionpostgres.New(runtime)
	sessionSvc := sessionservice.New(clock.UTCClock{}, sessions, tokens, sessionservice.Config{SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour, SessionRefreshThreshold: time.Minute})
	coordinator := sessionservice.NewLogin(sessionSvc, login)
	proof := mfaservice.PrimaryProof{UserID: f.user, AuthVersion: 2, Method: "password", Reference: "old-hash", VerifiedAt: time.Now().UTC()}
	result, err := coordinator.BeginLogin(ctx, proof, "test", "192.0.2.1")
	if err != nil || result.Challenge == nil || !result.Challenge.EnrollmentRequired || result.RawToken != "" {
		t.Fatal("limited enrollment login missing", result, err)
	}
	challenge := result.Challenge
	w := httptest.NewRecorder()
	mfahttp.RespondChallenge(w, challenge)
	if w.Code != 202 || !strings.Contains(w.Body.String(), "mfa_enrollment_required") {
		t.Fatal("challenge response missing enrollment status", w.Body.String())
	}
	if _, err := login.Complete(ctx, mfaservice.CompleteLoginInput{Token: challenge.Token, Binding: challenge.Binding, Recovery: true, Code: strings.Repeat("a", 32)}); !errors.Is(err, mfadomain.ErrInvalidCode) {
		t.Fatal("enrollment challenge entered normal MFA completion", err)
	}
	management := mfaservice.New(repo, cipher, mfatotp.Authenticator{}, mfaTestLimit{}, "Role MFA test")
	cfg := &config.Config{}
	cfg.MFA.Enabled = true
	cfg.Browser.AllowedOrigins = []string{"https://auth.example.com"}
	routes := router.New(router.Handlers{Config: cfg, Logger: zap.NewNop(), MFA: mfahttp.New(management, login, zap.NewNop()), Middleware: sessionhttp.New(sessionSvc, zap.NewNop()), Session: sessionhttp.NewHandler(sessionservice.NewManagement(sessions), zap.NewNop())})
	request := func(path, body, binding, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "https://auth.example.com/api/v1/auth"+path, strings.NewReader(body))
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		if binding != "" {
			r.AddCookie(&http.Cookie{Name: mfahttp.LoginCookie, Value: binding})
		}
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, r)
		return w
	}
	body := `{"challenge":"` + challenge.Token + `"}`
	if w := request("/mfa/login/enrollment", body, challenge.Binding, "https://evil.example"); w.Code != 403 {
		t.Fatal("enrollment bypassed Origin", w.Code)
	}
	if w := request("/mfa/login/enrollment", body, "", "https://auth.example.com"); w.Code != 400 {
		t.Fatal("missing browser binding accepted", w.Code)
	}
	accessExec(t, db, ctx, `UPDATE auth.auth_settings SET password_enabled=false`)
	if w := request("/mfa/login/enrollment", body, challenge.Binding, "https://auth.example.com"); w.Code != 404 {
		t.Fatal("disabled primary continued enrollment", w.Code, w.Body.String())
	}
	accessExec(t, db, ctx, `UPDATE auth.auth_settings SET password_enabled=true`)
	response := request("/mfa/login/enrollment", body, challenge.Binding, "https://auth.example.com")
	var enrollment mfahttp.EnrollmentResponse
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &enrollment) != nil || enrollment.Secret == "" || enrollment.ExpiresAt.After(challenge.ExpiresAt) {
		t.Fatal("enrollment response invalid", response.Code, response.Body.String())
	}
	// A challenge cannot be used as a business session.
	r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/api/v1/auth/me", nil)
	r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: challenge.Token})
	w = httptest.NewRecorder()
	routes.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("limited challenge became a full session", w.Code)
	}
	params := mfaservice.LoginEnrollmentParams{ChallengeDigest: cipher.Digest("login:" + challenge.Token), BindingHash: cipher.Digest("browser:" + challenge.Binding), EnrollmentDigest: cipher.Digest("enrollment:" + enrollment.Token)}
	for range 5 {
		if err := repo.ConfirmLoginEnrollment(ctx, params, func([]byte, int64, time.Time) (int64, error) { return 0, mfadomain.ErrInvalidCode }, nil); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("wrong TOTP accepted", err)
		}
	}
	var attempts int
	if err := db.QueryRow(ctx, `SELECT attempts FROM auth.mfa_enrollments WHERE user_id=$1`, f.user).Scan(&attempts); err != nil || attempts != 5 {
		t.Fatal("wrong TOTP attempt rolled back", attempts, err)
	}
	called := false
	if err := repo.ConfirmLoginEnrollment(ctx, params, func([]byte, int64, time.Time) (int64, error) { called = true; return 0, nil }, nil); !errors.Is(err, mfadomain.ErrInvalidCode) || called {
		t.Fatal("sixth attempt reached TOTP check", err)
	}
	response = request("/mfa/login/enrollment", body, challenge.Binding, "https://auth.example.com")
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &enrollment) != nil || enrollment.ExpiresAt.After(challenge.ExpiresAt) {
		t.Fatal("bounded enrollment restart failed", response.Code)
	}
	confirmBody := `{"challenge":"` + challenge.Token + `","token":"` + enrollment.Token + `","code":"` + mfaCode(t, db, ctx, enrollment.Secret, 0) + `"}`
	accessExec(t, db, ctx, `UPDATE auth.auth_settings SET password_enabled=false`)
	if w := request("/mfa/login/enrollment/confirm", confirmBody, challenge.Binding, "https://auth.example.com"); w.Code != 404 {
		t.Fatal("disabled primary completed enrollment", w.Code)
	}
	accessExec(t, db, ctx, `UPDATE auth.auth_settings SET password_enabled=true`)
	accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit ADD CONSTRAINT reject_role_enrollment CHECK(event<>'totp_enabled') NOT VALID`)
	if w := request("/mfa/login/enrollment/confirm", confirmBody, challenge.Binding, "https://auth.example.com"); w.Code != 503 {
		t.Fatal("failed audit exposed success", w.Code)
	}
	var intact bool
	if err := db.QueryRow(ctx, `SELECT auth_version=2 AND NOT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)
		AND EXISTS(SELECT 1 FROM auth.mfa_login_challenges WHERE user_id=$1) FROM auth.users WHERE id=$1`, f.user).Scan(&intact); err != nil || !intact {
		t.Fatal("enrollment audit failure was not atomic", err)
	}
	accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit DROP CONSTRAINT reject_role_enrollment`)
	var wg sync.WaitGroup
	results := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		wg.Go(func() {
			results <- request("/mfa/login/enrollment/confirm", confirmBody, challenge.Binding, "https://auth.example.com")
		})
	}
	wg.Wait()
	close(results)
	var codes mfahttp.RecoveryCodesResponse
	successes := 0
	for w := range results {
		if w.Code == 200 {
			successes++
			if err := json.Unmarshal(w.Body.Bytes(), &codes); err != nil {
				t.Fatal(err)
			}
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == sessionhttp.SessionCookieName && cookie.Value != "" {
					t.Fatal("enrollment issued session")
				}
			}
		} else if w.Code != 400 {
			t.Fatal("unexpected concurrent confirmation", w.Code, w.Body.String())
		}
	}
	if successes != 1 || len(codes.Codes) != mfadomain.RecoveryCodeCount {
		t.Fatal("enrollment had multiple winners/missing codes", successes)
	}
	if w := request("/mfa/login/enrollment/confirm", confirmBody, challenge.Binding, "https://auth.example.com"); w.Code != 400 {
		t.Fatal("enrollment replay accepted", w.Code)
	}
	proof.AuthVersion = 3
	proof.VerifiedAt = time.Now().UTC()
	result, err = coordinator.BeginLogin(ctx, proof, "test", "")
	if err != nil || result.Challenge == nil || result.Challenge.EnrollmentRequired {
		t.Fatal("enrolled user did not get normal MFA challenge", result, err)
	}
	logged, err := login.Complete(ctx, mfaservice.CompleteLoginInput{Token: result.Challenge.Token, Binding: result.Challenge.Binding, Recovery: true, Code: codes.Codes[0]})
	if err != nil {
		t.Fatal("new primary plus MFA failed", err)
	}
	replacement := tokens.Hash("fresh-role-mfa-proof")
	if _, err := sessions.ConfirmPassword(ctx, f.user, tokens.Hash(logged.Token), "old-hash", 3, replacement); err != nil {
		t.Fatal(err)
	}
	if err := repo.Disable(ctx, mfaservice.Proof{UserID: f.user, AuthVersion: 3, TokenHash: replacement}); !errors.Is(err, mfadomain.ErrRequiredByPolicy) {
		t.Fatal("required MFA disabled", err)
	}
	required := false
	role, err = access.UpdateRole(ctx, accessservice.UpdateRoleInput{CreateRoleInput: accessservice.CreateRoleInput{Actor: actor, Key: role.Key, Name: role.Name, Permissions: role.Permissions, MFARequired: &required}, RoleID: role.ID, ExpectedVersion: role.Version})
	if err != nil || role.MFARequired {
		t.Fatal("policy relaxation failed", err)
	}
	if _, err := sessions.FindSession(ctx, replacement); err != nil {
		t.Fatal("relaxation invalidated MFA session", err)
	}
	if err := repo.Disable(ctx, mfaservice.Proof{UserID: f.user, AuthVersion: 3, TokenHash: replacement}); err != nil {
		t.Fatal("optional MFA could not be disabled with proofs", err)
	}
}
