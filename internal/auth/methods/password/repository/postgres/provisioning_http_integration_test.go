package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	requestmiddleware "github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

type issuanceHasher struct {
	temporaryFixtureHash
	before func()
}

func (h *issuanceHasher) GenerateHash(ctx context.Context, raw []byte) (string, error) {
	if h.before != nil {
		h.before()
	}
	return h.temporaryFixtureHash.GenerateHash(ctx, raw)
}

func TestAdminProvisioningSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	accessExec(t, db, ctx, `CREATE ROLE auth_admin_users_runtime LOGIN PASSWORD 'synthetic-recovery-only';
		GRANT USAGE ON SCHEMA auth TO auth_admin_users_runtime;
		GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA auth TO auth_admin_users_runtime`)
	t.Cleanup(func() {
		migrateFixture(t, db, ctx, "down")
		accessExec(t, db, ctx, `DROP ROLE auth_admin_users_runtime`)
	})
	// A different default must not turn the authorization-after-lock check into a stale snapshot.
	accessExec(t, db, ctx, `ALTER ROLE auth_admin_users_runtime SET default_transaction_isolation='repeatable read'`)
	runtime := operatorPool(t, ctx, db, "auth_admin_users_runtime")
	fixture := newInvitationFixture(t, db, ctx, "admin-http")
	tokens := tokengenerate.New()
	raw, err := tokens.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	actor := fixture.input.Actor
	actor.TokenHash = tokens.Hash(raw)
	accessExec(t, db, ctx, `UPDATE auth.sessions SET token_hash=$2 WHERE user_id=$1`, actor.UserID, actor.TokenHash)
	accounts := accountpostgres.NewWithDelivery(runtime, accountpostgres.DeliveryConfig{Invitations: true})
	account := accountservice.New(accounts, verificationLimits{}, fixture.cipher, nil, accountservice.Config{})
	invitationCfg := accountservice.InvitationConfig{Enabled: true, URL: "https://app.example.com/activate", TTL: time.Hour, ReissueCooldown: time.Minute}
	provision := accountservice.NewProvisioning(accounts, account, invitationCfg)
	cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "password-reset:v1")
	if err != nil {
		t.Fatal(err)
	}
	hash := &issuanceHasher{}
	tempRepo := NewTemporaryPassword(runtime, accounts.ProvisionInTransaction)
	tempCfg := passwordservice.TemporaryPasswordConfig{Enabled: true, TTL: time.Hour, SetupTTL: 5 * time.Minute, ReissueCooldown: time.Minute, IssueActorAttemptsPerMinute: 100, IssueProjectAttemptsPerMinute: 1000}
	temporary := passwordservice.NewTemporaryPassword(tempRepo, hash, verificationLimits{}, cipher.Digest, nil, tempCfg)
	sessions := sessionservice.New(clock.UTCClock{}, sessionpostgres.New(runtime), tokens, sessionservice.Config{AbsoluteSessionTTL: 24 * time.Hour})
	h := router.New(router.Handlers{
		Provisioning: accounthttp.NewProvisioning(provision, zap.NewNop()), TemporaryAdmin: passwordhttp.NewTemporaryAdmin(temporary, zap.NewNop()),
		Middleware: sessionhttp.New(sessions, zap.NewNop()),
		Config:     &config.Config{MFA: mfaservice.Config{Enabled: true}, Invitation: invitationCfg, TemporaryPassword: tempCfg, Browser: requestmiddleware.OriginConfig{AllowedOrigins: []string{"https://localhost:8443"}}},
	})
	send := func(path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://localhost:8443/api/v1/admin/users"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://localhost:8443")
		r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: raw})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	check := func(w *httptest.ResponseRecorder, status int) {
		t.Helper()
		if w.Code != status || len(w.Result().Cookies()) != 0 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("HTTP result", w.Code, w.Body.String())
		}
	}
	key := func() string { return temporaryRequestKey(t, db, ctx) }
	inviteKey := key()
	inviteBody := fmt.Sprintf(`{"idempotencyKey":%q,"email":"admin-invited@example.com","invite":true}`, inviteKey)
	created := send("", inviteBody)
	check(created, 201)
	var invited accounthttp.ProvisionResponse
	if err := json.Unmarshal(created.Body.Bytes(), &invited); err != nil {
		t.Fatal(err)
	}
	check(send("", inviteBody), 200)
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.account_invitations WHERE user_id=$1`, invited.UserID).Scan(&count); err != nil || count != 1 {
		t.Fatal("replay duplicated invitation", count, err)
	}
	bareBody := fmt.Sprintf(`{"idempotencyKey":%q}`, key())
	bare := send("", bareBody)
	check(bare, 201)
	var bareUser accounthttp.ProvisionResponse
	if err := json.Unmarshal(bare.Body.Bytes(), &bareUser); err != nil {
		t.Fatal(err)
	}
	var pending bool
	if err := db.QueryRow(ctx, `SELECT status='pending'
		AND NOT EXISTS(SELECT 1 FROM auth.user_emails WHERE user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM auth.password_credentials WHERE user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM auth.user_roles WHERE user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM auth.sessions WHERE user_id=$1) FROM auth.users WHERE id=$1`, bareUser.UserID).Scan(&pending); err != nil || !pending {
		t.Fatal("bare creation granted authority", err)
	}
	invitePath := "/" + string(invited.UserID) + "/invitation"
	resendBody := fmt.Sprintf(`{"idempotencyKey":%q}`, key())
	check(send(invitePath, resendBody), 409)
	accessExec(t, db, ctx, `UPDATE auth.account_provisions SET last_invited_at=clock_timestamp()-interval '2 minutes' WHERE user_id=$1`, invited.UserID)
	check(send(invitePath, resendBody), 200)
	check(send(invitePath, resendBody), 200)
	tempBody := fmt.Sprintf(`{"idempotencyKey":%q,"email":"admin-temporary@example.com"}`, key())
	first := send("/temporary-password", tempBody)
	check(first, 201)
	var issued passwordhttp.TemporaryIssueResponse
	if err := json.Unmarshal(first.Body.Bytes(), &issued); err != nil || len(issued.Password) != 43 {
		t.Fatal("temporary issuance", err)
	}
	replay := send("/temporary-password", tempBody)
	check(replay, 200)
	if strings.Contains(replay.Body.String(), `"password"`) || strings.Contains(replay.Body.String(), `"expiresAt"`) {
		t.Fatal("creation replay exposed secret or fictitious expiry")
	}
	tempPath := "/" + string(issued.UserID) + "/temporary-password"
	reissueBody := fmt.Sprintf(`{"idempotencyKey":%q}`, key())
	check(send(tempPath, reissueBody), 409)
	accessExec(t, db, ctx, `UPDATE auth.account_provisions SET temporary_password_issued_at=clock_timestamp()-interval '2 minutes' WHERE user_id=$1`, issued.UserID)
	reissued := send(tempPath, reissueBody)
	check(reissued, 200)
	if !strings.Contains(reissued.Body.String(), `"password"`) {
		t.Fatal("reissue omitted first secret")
	}
	replay = send(tempPath, reissueBody)
	check(replay, 200)
	if strings.Contains(replay.Body.String(), `"password"`) || !strings.Contains(replay.Body.String(), `"expiresAt"`) {
		t.Fatal("reissue replay contract")
	}
	for _, proof := range []string{"password_verified_at", "mfa_verified_at"} {
		accessExec(t, db, ctx, `UPDATE auth.sessions SET `+proof+`=NULL WHERE user_id=$1`, actor.UserID)
		for _, request := range []struct{ path, body string }{{"", inviteBody}, {invitePath, resendBody}, {"/temporary-password", tempBody}, {tempPath, reissueBody}} {
			check(send(request.path, request.body), 403)
		}
		accessExec(t, db, ctx, `UPDATE auth.sessions SET `+proof+`=clock_timestamp() WHERE user_id=$1`, actor.UserID)
	}
	if err := mfapostgres.New(runtime).Disable(ctx, mfaservice.Proof{UserID: actor.UserID, TokenHash: actor.TokenHash, AuthVersion: 1}); !errors.Is(err, mfadomain.ErrRequiredByPolicy) {
		t.Fatal("users.manage holder disabled MFA", err)
	}
	// A role revoke after guarded preflight but during hashing must prevent the write.
	hash.before = func() { accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE user_id=$1`, actor.UserID) }
	raceKey := key()
	check(send("/temporary-password", fmt.Sprintf(`{"idempotencyKey":%q,"email":"revoked-during-hash@example.com"}`, raceKey)), 403)
	hash.before = nil
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.account_provisions WHERE actor_id=$1 AND request_key=$2`, actor.UserID, raceKey).Scan(&count); err != nil || count != 0 {
		t.Fatal("write after revoked authority", err)
	}
	for _, request := range []struct{ path, body string }{{"", inviteBody}, {invitePath, resendBody}, {"/temporary-password", tempBody}, {tempPath, reissueBody}} {
		check(send(request.path, request.body), 403)
	}
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM auth.roles WHERE key='provision_operator'`, actor.UserID)
	// Required audit is part of the account and temporary credential transaction.
	for _, temporaryProfile := range []bool{false, true} {
		table, action, path := "invitation_audit", "action<>'provisioned'", ""
		if temporaryProfile {
			table, action, path = "password_audit", "event<>'temporary_password_issued'", "/temporary-password"
		}
		accessExec(t, db, ctx, `ALTER TABLE auth.`+table+` ADD CONSTRAINT reject_admin_provision CHECK (`+action+`) NOT VALID`)
		commandKey := key()
		body := fmt.Sprintf(`{"idempotencyKey":%q,"email":"rollback-admin-%t@example.com"}`, commandKey, temporaryProfile)
		check(send(path, body), 503)
		accessExec(t, db, ctx, `ALTER TABLE auth.`+table+` DROP CONSTRAINT reject_admin_provision`)
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.account_provisions WHERE actor_id=$1 AND request_key=$2`, actor.UserID, commandKey).Scan(&count); err != nil || count != 0 {
			t.Fatal("audit failure left a command", err)
		}
	}
	// One command across concurrent HTTP requests returns one UUID and one plaintext secret.
	parallelBody := fmt.Sprintf(`{"idempotencyKey":%q,"email":"parallel-admin@example.com"}`, key())
	var wg sync.WaitGroup
	results := make(chan *httptest.ResponseRecorder, 16)
	for range 16 {
		wg.Go(func() { results <- send("/temporary-password", parallelBody) })
	}
	wg.Wait()
	close(results)
	winners := 0
	var userID string
	for response := range results {
		if response.Code != 200 && response.Code != 201 {
			t.Fatal("concurrent issuance", response.Code, response.Body.String())
		}
		var result passwordhttp.TemporaryIssueResponse
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if userID == "" {
			userID = string(result.UserID)
		} else if userID != string(result.UserID) {
			t.Fatal("duplicate user UUID")
		}
		if result.Password != "" {
			winners++
		}
	}
	if winners != 1 {
		t.Fatal("plaintext winners", winners)
	}
	// Wait behind a committed role revoke: a stale repeatable-read snapshot must not authorize replay.
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:gosec // Commit closes the transaction; preserve an earlier test failure.
	if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM auth.user_roles WHERE user_id=$1`, actor.UserID); err != nil {
		t.Fatal(err)
	}
	waited := make(chan *httptest.ResponseRecorder, 1)
	go func() { waited <- send("/temporary-password", tempBody) }()
	var waiting bool
	until := time.Now().Add(2 * time.Second)
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	for time.Now().Before(until) {
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='auth_admin_users_runtime' AND wait_event='advisory')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case <-poll.C:
		case <-ctx.Done():
			t.Fatal("permission wait observation timed out")
		}
	}
	if !waiting {
		t.Fatal("HTTP replay did not wait behind Access mutation")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-waited:
		check(response, 403)
	case <-ctx.Done():
		t.Fatal("replay did not finish after permission revoke")
	}
	wrongActor := actor
	wrongActor.TokenHash = strings.Repeat("0", 64)
	if _, err := tempRepo.FindTemporaryProvision(ctx, accountservice.ProvisionCommand{Input: accountservice.ProvisionInput{Actor: wrongActor, IdempotencyKey: inviteKey}}); !errors.Is(err, accessdomain.ErrFreshAuthRequired) {
		t.Fatal("direct replay bypassed session authority", err)
	}
}
