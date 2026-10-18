package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	operatorpostgres "github.com/Inforberi/financial-intelligence/internal/platform/operator/repository/postgres"
)

func operatorRecoveryPools(t *testing.T, admin *pgxpool.Pool) (*pgxpool.Pool, *pgxpool.Pool) {
	t.Helper()
	ctx := t.Context()
	var absent bool
	if err := admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN
		('auth_recovery_operator','auth_mfa_recovery_operator','platform_password_recovery_operator','platform_mfa_recovery_operator','platform_password_test','platform_mfa_test'))`).Scan(&absent); err != nil || !absent {
		t.Fatal("offline fixture identities already exist", err)
	}
	if _, err := admin.Exec(ctx, `CREATE ROLE auth_recovery_operator NOLOGIN; CREATE ROLE auth_mfa_recovery_operator NOLOGIN;
		CREATE ROLE platform_password_recovery_operator NOLOGIN; CREATE ROLE platform_mfa_recovery_operator NOLOGIN;
		CREATE ROLE platform_password_test LOGIN PASSWORD 'fixture-offline-only'; CREATE ROLE platform_mfa_test LOGIN PASSWORD 'fixture-offline-only';
		GRANT platform_password_recovery_operator TO platform_password_test; GRANT platform_mfa_recovery_operator TO platform_mfa_test`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, err := admin.Exec(context.Background(), `DROP OWNED BY platform_password_test,platform_mfa_test,platform_password_recovery_operator,platform_mfa_recovery_operator,auth_recovery_operator,auth_mfa_recovery_operator;
			DROP ROLE platform_password_test,platform_mfa_test,platform_password_recovery_operator,platform_mfa_recovery_operator,auth_recovery_operator,auth_mfa_recovery_operator`)
		if err != nil {
			t.Error("offline fixture cleanup", err)
		}
	})
	root := os.Getenv("AUTH_OPERATOR_TEST_ROOT")
	if root == "" {
		root = filepath.Join("..", "..", "..")
	}
	for _, name := range []string{"recovery-grants.sql", "mfa-recovery-grants.sql", "platform-recovery-grants.sql"} {
		data, err := os.ReadFile(filepath.Join(root, "deploy", name))
		if err != nil {
			t.Fatal(err)
		}
		grants := strings.NewReplacer("DATABASE auth TO", "DATABASE auth_platform_test TO", "DATABASE auth_platform ", "DATABASE auth_platform_test ").Replace(string(data))
		if name == "recovery-grants.sql" {
			grants = strings.ReplaceAll(grants, "auth_recovery_operator", "platform_password_recovery_operator")
		}
		if name == "mfa-recovery-grants.sql" {
			grants = strings.ReplaceAll(grants, "auth_mfa_recovery_operator", "platform_mfa_recovery_operator")
		}
		if _, err := admin.Exec(ctx, grants); err != nil {
			t.Fatal("offline grants", err)
		}
	}
	open := func(user string) *pgxpool.Pool {
		cfg := admin.Config()
		cfg.ConnConfig.User = user
		cfg.MaxConns = 1
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		return pool
	}
	return open("platform_password_test"), open("platform_mfa_test")
}

func operatorRecoveryDrill(t *testing.T, admin *pgxpool.Pool, deps realmDependencies, cfg *config.Config, mail *operatorMailbox, h *operatorHTTPS, user accountdomain.UserID, old *http.Cookie, oldRecoveryCode string) *http.Cookie {
	t.Helper()
	ctx := t.Context()
	notReady := *cfg
	notReady.MFA.RecoveryEnabled = true
	if _, err := assembleOperator(ctx, &notReady, deps, mail); err == nil {
		t.Fatal("recovery enabled without offline grants")
	}
	passwordPool, mfaPool := operatorRecoveryPools(t, admin)
	guard := func(pool *pgxpool.Pool, realm operatordomain.RealmID, mfa, want bool) {
		t.Helper()
		repo, err := operatorpostgres.New(pool, realm)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.CheckRecovery(ctx, user, mfa); (err == nil) != want {
			t.Fatal("offline realm guard", want, err)
		}
	}
	realm := operatordomain.RealmID(cfg.Platform.RealmID)
	guard(passwordPool, realm, false, true)
	guard(mfaPool, realm, true, true)
	guard(deps.pool, realm, false, false)
	guard(admin, realm, false, false)
	guard(passwordPool, "11111111-1111-4111-8111-111111111111", false, false)
	guard(passwordPool, realm, true, false)
	guard(mfaPool, realm, false, false)
	if _, err := admin.Exec(ctx, `GRANT auth_recovery_operator TO platform_password_recovery_operator WITH INHERIT TRUE, SET TRUE`); err != nil {
		t.Fatal(err)
	}
	guard(passwordPool, realm, false, false)
	if _, err := admin.Exec(ctx, `GRANT auth_recovery_operator TO platform_password_recovery_operator WITH INHERIT FALSE, SET FALSE`); err != nil {
		t.Fatal(err)
	}
	var isolated bool
	if err := admin.QueryRow(ctx, `SELECT pg_has_role('platform_password_test','auth_recovery_operator','MEMBER')
		AND NOT pg_has_role('platform_password_test','auth_recovery_operator','USAGE')
		AND NOT pg_has_role('platform_password_test','auth_recovery_operator','SET')
		AND NOT has_function_privilege('auth_mfa_recovery_operator','auth.decide_mfa_recovery(uuid,uuid,bigint,boolean,text,text)','EXECUTE')
		AND NOT has_table_privilege('auth_recovery_operator','platform.operator_realm','SELECT')`).Scan(&isolated); err != nil || !isolated {
		t.Fatal("cluster-wide project groups gained platform rights", err)
	}
	if _, err := admin.Exec(ctx, `GRANT auth_recovery_operator TO auth_platform_operator_test`); err != nil {
		t.Fatal(err)
	}
	runtimeGuard, err := operatorpostgres.New(deps.pool, realm)
	if err != nil {
		t.Fatal(err)
	}
	unsafeRuntime := runtimeGuard.CheckRuntime(ctx, false)
	if _, err := admin.Exec(ctx, `REVOKE auth_recovery_operator FROM auth_platform_operator_test`); err != nil {
		t.Fatal(err)
	}
	if unsafeRuntime == nil {
		t.Fatal("runtime accepted emergency membership")
	}
	if _, err := admin.Exec(ctx, `GRANT SELECT ON auth.mfa_totp TO platform_password_test`); err != nil {
		t.Fatal(err)
	}
	guard(passwordPool, realm, false, false)
	if _, err := admin.Exec(ctx, `REVOKE SELECT ON auth.mfa_totp FROM platform_password_test`); err != nil {
		t.Fatal(err)
	}
	var savedSecret []byte
	if err := admin.QueryRow(ctx, `SELECT secret FROM auth.mfa_totp WHERE user_id=$1`, user).Scan(&savedSecret); err != nil {
		t.Fatal(err)
	}
	if err := passwordPool.QueryRow(ctx, `SELECT secret FROM auth.mfa_totp WHERE user_id=$1`, user).Scan(new([]byte)); err == nil {
		t.Fatal("offline password login read the factor")
	}
	reset := passwordservice.NewOperatorRecovery(passwordpostgres.New(passwordPool), deps.hash)
	target, err := reset.Preview(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	request := passworddomain.OperatorRecovery{UserID: user, ExpectedVersion: target.AuthVersion, Environment: "test", Reason: "fixture-incident"}
	if _, err := reset.Reset(ctx, request, []byte("EmergencyPassword3")); err != nil {
		t.Fatal("platform password recovery", err)
	}
	if _, err := reset.Reset(ctx, request, []byte("EmergencyPassword4")); !errors.Is(err, passworddomain.ErrOperatorRecoveryConflict) {
		t.Fatal("stale reset accepted", err)
	}
	var keptSecret []byte
	if err := admin.QueryRow(ctx, `SELECT secret FROM auth.mfa_totp WHERE user_id=$1`, user).Scan(&keptSecret); err != nil || !bytes.Equal(savedSecret, keptSecret) {
		t.Fatal("password reset changed MFA", err)
	}
	password := "EmergencyPassword3"
	if os.Getenv("AUTH_OPERATOR_TEST_CLI") != "" {
		operatorPasswordCLI(t, cfg.Platform.RealmID, user, target.AuthVersion+1)
		password = "PlatformClilogin4"
	}
	h.call("GET", "/api/v1/auth/me", nil, []*http.Cookie{old}, 401)
	cfg.MFA.RecoveryEnabled = true
	assembled, err := assembleOperator(ctx, cfg, deps, mail)
	if err != nil {
		t.Fatal("recovery-enabled assembly", err)
	}
	t.Cleanup(assembled.resources.close)
	h = newOperatorHTTPS(t, assembled.handler, cfg.Platform.Origin)
	loginInput := map[string]string{"email": "operator@example.test", "password": password}
	login, cookies := h.call("POST", "/api/v1/admin/auth/login/email", loginInput, nil, 202)
	binding := operatorCookie(t, cookies, "__Host-mfa-login")
	_, sessionCookies := h.call("POST", "/api/v1/auth/mfa/login/complete", map[string]any{"challenge": operatorField(t, login, "challenge"), "code": oldRecoveryCode, "recovery": true}, []*http.Cookie{binding}, 200)
	beforeMFARecovery := operatorCookie(t, sessionCookies, sessionhttp.SessionCookieName)
	login, cookies = h.call("POST", "/api/v1/admin/auth/login/email", loginInput, nil, 202)
	binding = operatorCookie(t, cookies, "__Host-mfa-login")
	challenge := operatorField(t, login, "challenge")
	candidate, _ := h.call("POST", "/api/v1/auth/mfa/recovery/start", map[string]string{"challenge": challenge}, []*http.Cookie{binding}, 200)
	var now time.Time
	if err := admin.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(operatorField(t, candidate, "secret"), now)
	if err != nil {
		t.Fatal(err)
	}
	complete := map[string]string{"challenge": challenge, "requestId": operatorField(t, candidate, "requestId"), "code": code}
	h.call("POST", "/api/v1/auth/mfa/recovery/complete", complete, []*http.Cookie{binding}, 400)
	decisions := mfaservice.NewRecoveryOperator(mfapostgres.New(mfaPool))
	preview, err := decisions.Preview(ctx, user, complete["requestId"])
	if err != nil {
		t.Fatal(err)
	}
	decision := mfadomain.RecoveryDecision{UserID: user, RequestID: complete["requestId"], ExpectedVersion: preview.AuthVersion, Approve: true, Environment: "test", Reason: "independent-fixture-verification"}
	if os.Getenv("AUTH_OPERATOR_TEST_CLI") != "" {
		operatorMFACLI(t, cfg.Platform.RealmID, decision)
	} else {
		if err := decisions.Decide(ctx, decision); err != nil {
			t.Fatal(err)
		}
	}
	if err := decisions.Decide(ctx, decision); err == nil {
		t.Fatal("replayed approval accepted")
	}
	if _, err := admin.Exec(ctx, `REVOKE platform_mfa_recovery_operator FROM platform_mfa_test`); err != nil {
		t.Fatal(err)
	}
	h.call("POST", "/api/v1/auth/mfa/recovery/complete", complete, []*http.Cookie{binding}, 400)
	if _, err := admin.Exec(ctx, `GRANT platform_mfa_recovery_operator TO platform_mfa_test`); err != nil {
		t.Fatal(err)
	}
	result, issued := h.call("POST", "/api/v1/auth/mfa/recovery/complete", complete, []*http.Cookie{binding}, 200)
	h.call("GET", "/api/v1/auth/me", nil, []*http.Cookie{beforeMFARecovery}, 401)
	for _, cookie := range issued {
		if cookie.Value != "" && cookie.Name == sessionhttp.SessionCookieName {
			t.Fatal("MFA recovery issued a session")
		}
	}
	h.call("POST", "/api/v1/auth/mfa/recovery/complete", complete, []*http.Cookie{binding}, 400)
	var markerUnchanged, audited bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform.operator_realm WHERE id=$1 AND first_operator_id=$2 AND initialized_at IS NOT NULL),
		EXISTS(SELECT 1 FROM auth.mfa_audit WHERE user_id=$2 AND event='recovery_completed')`, realm, user).Scan(&markerUnchanged, &audited); err != nil || !markerUnchanged || !audited {
		t.Fatal("recovery marker/audit", err)
	}
	security := realmSecurity{scope: deps.scope}
	cipher, err := security.cipher(cfg.Account.EncryptionKey, "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cipher.Open(savedSecret); err != nil {
		t.Fatal("original platform factor was not scoped", err)
	}
	legacy, _ := (realmSecurity{scope: realmscope.Legacy()}).cipher(cfg.Account.EncryptionKey, "mfa:v1")
	if _, err := legacy.Open(savedSecret); err == nil {
		t.Fatal("platform ciphertext opened in legacy scope")
	}
	var codes []string
	if err := json.Unmarshal(result["codes"], &codes); err != nil || len(codes) != 10 {
		t.Fatal("new recovery codes", err)
	}
	login, cookies = h.call("POST", "/api/v1/admin/auth/login/email", loginInput, nil, 202)
	binding = operatorCookie(t, cookies, "__Host-mfa-login")
	_, cookies = h.call("POST", "/api/v1/auth/mfa/login/complete", map[string]any{"challenge": operatorField(t, login, "challenge"), "code": codes[0], "recovery": true}, []*http.Cookie{binding}, 200)
	session := operatorCookie(t, cookies, sessionhttp.SessionCookieName)
	h.call("GET", "/api/v1/auth/me", nil, []*http.Cookie{session}, 200)
	return session
}
