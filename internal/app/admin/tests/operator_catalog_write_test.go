package admin_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	operatorpostgres "github.com/Inforberi/financial-intelligence/internal/admin/administrators/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func operatorCatalogWriteDrill(t *testing.T, admin, runtime *pgxpool.Pool, authority *operatorpostgres.Repository, h *operatorHTTPS, actor operatordomain.Principal, session *http.Cookie) {
	t.Helper()
	ctx := t.Context()
	const project = "11111111-1111-4111-8111-111111111111"
	path := "/api/v1/platform/projects/" + project
	cookies := []*http.Cookie{session}
	var before, after string
	if err := admin.QueryRow(ctx, `SELECT to_jsonb(s)::text FROM auth.sessions s WHERE token_hash=$1`, actor.TokenHash).Scan(&before); err != nil {
		t.Fatal(err)
	}
	input := func(op, version int) map[string]any {
		return map[string]any{"operationId": fmt.Sprintf("55555555-5555-4555-8555-%012d", op), "expectedVersion": version, "expectedGeneration": version, "reason": "fixture-incident"}
	}
	h.call("POST", path+"/suspend", input(1, 1), nil, 401)
	for _, body := range []any{nil, map[string]any{"actorId": actor.UserID}, input(1, 0)} {
		h.call("POST", path+"/suspend", body, cookies, 400)
	}
	first, issued := h.call("POST", path+"/suspend", input(1, 1), cookies, 200)
	if string(first["version"]) != "2" || string(first["generation"]) != "2" || string(first["replayed"]) != "false" || len(issued) != 0 {
		t.Fatal("invalid first transition receipt")
	}
	h.call("POST", path+"/resume", input(2, 2), cookies, 200)
	replay, _ := h.call("POST", path+"/suspend", input(1, 1), cookies, 200)
	if string(replay["version"]) != "2" || string(replay["replayed"]) != "true" || operatorField(t, replay, "desiredState") != "suspended" {
		t.Fatal("lost-reply replay did not return original receipt")
	}
	for _, tc := range []struct {
		suffix string
		body   map[string]any
	}{
		{"suspend", input(3, 1)}, {"resume", input(1, 1)}, {"resume", input(3, 3)}, {"retry", input(3, 3)},
	} {
		h.call("POST", path+"/"+tc.suffix, tc.body, cookies, 409)
	}
	h.call("POST", path+"/suspend?actor=forged", input(3, 3), cookies, 400)
	h.call("POST", "/api/v1/platform/projects/invalid/suspend", input(3, 1), cookies, 400)
	h.call("POST", "/api/v1/platform/projects/44444444-4444-4444-8444-444444444444/suspend", input(3, 1), cookies, 404)
	h.call("POST", "/api/v1/platform/projects/22222222-2222-4222-8222-222222222222/retry", input(4, 1), cookies, 200)
	h.call("POST", "/api/v1/platform/projects/33333333-3333-4333-8333-333333333333/resume", input(5, 1), cookies, 200)
	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM platform.project_events WHERE actor_kind='operator' AND actor_id=$1`, actor.UserID).Scan(&count); err != nil || count != 4 {
		t.Fatal("missing or duplicated audit", count, err)
	}
	if err := admin.QueryRow(ctx, `SELECT to_jsonb(s)::text FROM auth.sessions s WHERE token_hash=$1`, actor.TokenHash).Scan(&after); err != nil || before != after {
		t.Fatal("catalog mutations changed SQL session state", err)
	}
	if _, err := admin.Exec(ctx, `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.projects.manage'`, actor.UserID); err != nil {
		t.Fatal(err)
	}
	h.call("POST", path+"/suspend", input(1, 1), cookies, 403)
	h.call("POST", "/api/v1/platform/projects/44444444-4444-4444-8444-444444444444/suspend", input(3, 1), cookies, 403)
	h.call("GET", path, nil, cookies, 200)
	if _, err := admin.Exec(ctx, `INSERT INTO platform.operator_permissions VALUES($1,'platform.projects.manage')`, actor.UserID); err != nil {
		t.Fatal(err)
	}
	hash := tokengenerate.New().Hash(session.Value)
	// Backdate only this synthetic session so stale proofs still satisfy issuance invariants.
	if _, err := admin.Exec(ctx, `UPDATE auth.sessions SET created_at=created_at-interval '7 minutes',primary_verified_at=clock_timestamp()-interval '7 minutes' WHERE token_hash=$1`, hash); err != nil {
		t.Fatal(err)
	}
	for _, proof := range []string{"password_verified_at", "mfa_verified_at"} {
		if _, err := admin.Exec(ctx, `UPDATE auth.sessions SET `+proof+`=clock_timestamp()-interval '6 minutes' WHERE token_hash=$1`, hash); err != nil {
			t.Fatal(err)
		}
		h.call("POST", path+"/suspend", input(1, 1), cookies, 428)
		h.call("GET", path, nil, cookies, 200)
		if _, err := admin.Exec(ctx, `UPDATE auth.sessions SET `+proof+`=clock_timestamp() WHERE token_hash=$1`, hash); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx, `ALTER TABLE platform.project_events ADD CONSTRAINT fixture_reject_suspend CHECK(action<>'suspend') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	h.call("POST", path+"/suspend", input(6, 3), cookies, 503)
	if _, err := admin.Exec(ctx, `ALTER TABLE platform.project_events DROP CONSTRAINT fixture_reject_suspend`); err != nil {
		t.Fatal(err)
	}
	card, _ := h.call("GET", path, nil, cookies, 200)
	if string(card["version"]) != "3" || operatorField(t, card, "desiredState") != "enabled" {
		t.Fatal("audit failure committed state")
	}
	operatorMutationLocksDrill(t, admin, runtime, authority, actor)
}
