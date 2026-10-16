package postgres

import (
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
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	accesshttp "github.com/Inforberi/financial-intelligence/internal/access/transport/http"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	requestmiddleware "github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

func TestAccessHTTPSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	accessExec(t, db, ctx, `CREATE ROLE auth_access_http_runtime LOGIN PASSWORD 'synthetic-recovery-only';
		GRANT USAGE ON SCHEMA auth TO auth_access_http_runtime;
		GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA auth TO auth_access_http_runtime`)
	t.Cleanup(func() {
		migrateFixture(t, db, ctx, "down")
		accessExec(t, db, ctx, `DROP ROLE auth_access_http_runtime`)
	})
	runtime := operatorPool(t, ctx, db, "auth_access_http_runtime")
	catalog, err := settings.NewCatalog([]settings.Permission{{Key: "reports.read", Name: "Read reports"}, {Key: "secret.read", Name: "Read secrets"}})
	if err != nil {
		t.Fatal(err)
	}
	actor, target := accessPrincipal(t, db, ctx), accessPrincipal(t, db, ctx)
	tokens := tokengenerate.New()
	actorRaw, err := tokens.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	targetRaw, err := tokens.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `UPDATE auth.sessions SET token_hash=$2 WHERE user_id=$1`, actor.UserID, tokens.Hash(actorRaw))
	accessExec(t, db, ctx, `UPDATE auth.sessions SET token_hash=$2 WHERE user_id=$1`, target.UserID, tokens.Hash(targetRaw))
	var systemID string
	if err := db.QueryRow(ctx, `INSERT INTO auth.roles(key,name,system) VALUES('super_admin','Super admin',true) RETURNING id`).Scan(&systemID); err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) SELECT $1,unnest($2::text[])`, systemID, []string{"access.roles.manage", "access.assignments.manage", "reports.read"})
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2)`, actor.UserID, systemID)
	sessions := sessionservice.New(clock.UTCClock{}, sessionpostgres.New(runtime), tokens, sessionservice.Config{AbsoluteSessionTTL: 24 * time.Hour})
	svc := accessservice.New(accesspostgres.New(runtime), catalog)
	h := router.New(router.Handlers{
		Access: accesshttp.New(svc, zap.NewNop()), Middleware: sessionhttp.New(sessions, zap.NewNop()),
		Config: &config.Config{MFA: mfaservice.Config{Enabled: true}, Browser: requestmiddleware.OriginConfig{AllowedOrigins: []string{"https://localhost:8443"}}},
	})
	send := func(method, path, body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://localhost:8443/api/v1/"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://localhost:8443")
		r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: token})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	check := func(w *httptest.ResponseRecorder, status int) {
		t.Helper()
		if w.Code != status || w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 {
			t.Fatal("HTTP result", w.Code, w.Body.String())
		}
	}
	createBody := `{"key":"reader","name":"Reader","permissions":["reports.read"]}`
	created := send("POST", "admin/roles", createBody, actorRaw)
	check(created, 201)
	var role accesshttp.RoleResponse
	if err := json.Unmarshal(created.Body.Bytes(), &role); err != nil || role.ID == "" || role.Version != 1 {
		t.Fatal("created role contract", err)
	}
	rolePath := "admin/roles/" + string(role.ID)
	assignmentPath := "admin/users/" + string(target.UserID) + "/roles/" + string(role.ID)
	targetPath := "admin/users/" + string(target.UserID) + "/access"
	check(send("GET", "admin/roles?limit=1", "", actorRaw), 200)
	check(send("GET", rolePath, "", actorRaw), 200)
	check(send("GET", "admin/permissions", "", actorRaw), 200)
	check(send("GET", targetPath, "", actorRaw), 200)
	check(send("GET", targetPath, "", targetRaw), 403)
	check(send("GET", "admin/users/00000000-0000-4000-8000-000000000000/access", "", actorRaw), 403)
	check(send("POST", assignmentPath, `{"expectedRoleVersion":1,"expectedAccessVersion":1}`, actorRaw), 200)
	check(send("GET", "auth/access", "", targetRaw), 401)
	fresh := renewAccessPrincipal(t, db, ctx, target.UserID)
	targetRaw, err = tokens.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `UPDATE auth.sessions SET token_hash=$2 WHERE token_hash=$1`, fresh.TokenHash, tokens.Hash(targetRaw))
	access := send("GET", "auth/access", "", targetRaw)
	check(access, 200)
	if !strings.Contains(access.Body.String(), "reports.read") || !strings.Contains(access.Body.String(), `"accessVersion":2`) {
		t.Fatal("grant not effective", access.Body.String())
	}
	check(send("POST", assignmentPath, `{"expectedRoleVersion":1,"expectedAccessVersion":1}`, actorRaw), 409)
	check(send("POST", "admin/roles", `{"key":"leak","name":"Forbidden","permissions":["secret.read"]}`, actorRaw), 403)
	check(send("POST", "admin/roles", createBody, targetRaw), 403)
	check(send("GET", rolePath, "", targetRaw), 403)
	check(send("POST", "admin/users/"+string(actor.UserID)+"/roles/"+string(role.ID), `{"expectedRoleVersion":1,"expectedAccessVersion":1}`, actorRaw), 403)
	check(send("DELETE", "admin/users/"+string(actor.UserID)+"/roles/"+systemID, `{"expectedRoleVersion":1,"expectedAccessVersion":1}`, actorRaw), 403)
	for _, proof := range []string{"password_verified_at", "mfa_verified_at"} {
		accessExec(t, db, ctx, `UPDATE auth.sessions SET `+proof+`=NULL WHERE user_id=$1`, actor.UserID)
		check(send("POST", "admin/roles", `{"key":"no_proof","name":"No proof"}`, actorRaw), 403)
		check(send("GET", rolePath, "", actorRaw), 200)
		accessExec(t, db, ctx, `UPDATE auth.sessions SET `+proof+`=clock_timestamp() WHERE user_id=$1`, actor.UserID)
	}
	// Concurrent HTTP edits still use the existing SQL optimistic-version guard.
	var wg sync.WaitGroup
	results := make(chan int, 16)
	for i := range 16 {
		wg.Go(func() {
			body := fmt.Sprintf(`{"key":"reader","name":"Reader %d","permissions":["reports.read"],"expectedVersion":1}`, i)
			results <- send("POST", rolePath, body, actorRaw).Code
		})
	}
	wg.Wait()
	close(results)
	winners := 0
	for status := range results {
		if status == 200 {
			winners++
		} else if status != 409 {
			t.Fatal("concurrent update", status)
		}
	}
	if winners != 1 {
		t.Fatal("concurrent edit winners", winners)
	}
	check(send("DELETE", assignmentPath, `{"expectedRoleVersion":1,"expectedAccessVersion":2}`, actorRaw), 409)
	check(send("DELETE", assignmentPath, `{"expectedRoleVersion":2,"expectedAccessVersion":2}`, actorRaw), 200)
	access = send("GET", "auth/access", "", targetRaw)
	check(access, 200)
	if strings.Contains(access.Body.String(), "reports.read") || !strings.Contains(access.Body.String(), `"accessVersion":3`) {
		t.Fatal("revoke not effective", access.Body.String())
	}
	accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE user_id=$1`, actor.UserID)
	check(send("GET", "admin/permissions", "", actorRaw), 403)
	check(send("GET", targetPath, "", actorRaw), 403)
	check(send("POST", "admin/roles", `{"key":"revoked","name":"Revoked"}`, actorRaw), 403)
	var audits int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.access_audit WHERE role_id=$1`, role.ID).Scan(&audits); err != nil || audits != 4 {
		t.Fatal("audit count includes failed requests", audits, err)
	}
	if _, err := svc.AssignmentAccess(ctx, actor, target.UserID); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatal("direct service bypassed revoked permission", err)
	}
}
