package auth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func operatorCatalogReadDrill(t *testing.T, admin *pgxpool.Pool, h *operatorHTTPS, user accountdomain.UserID, session *http.Cookie) {
	t.Helper()
	ctx := t.Context()
	if _, err := admin.Exec(ctx, `INSERT INTO platform.projects(id,slug,name,origin,storage_target,phase,desired_state,database_name,credential_ref,schema_version,created_at,updated_at)
		VALUES ('11111111-1111-4111-8111-111111111111','shop','Shop','https://shop.auth.example','primary','pending','enabled',NULL,NULL,0,'2026-10-18T00:00:00Z','2026-10-18T00:00:00Z'),
		('22222222-2222-4222-8222-222222222222','failed-shop','Failed shop','https://failed.auth.example','primary','failed','enabled',NULL,NULL,0,'2026-10-18T00:00:00Z','2026-10-18T00:00:00Z'),
		('33333333-3333-4333-8333-333333333333','paused-shop','Paused shop','https://paused.auth.example','primary','ready','suspended','auth_hidden_fixture','hidden:credential:ref',1,'2026-10-18T00:00:00Z','2026-10-18T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	hash := tokengenerate.New().Hash(session.Value)
	var before, after string
	if err := admin.QueryRow(ctx, `SELECT to_jsonb(s)::text FROM auth.sessions s WHERE token_hash=$1`, hash).Scan(&before); err != nil {
		t.Fatal(err)
	}
	h.call("GET", "/api/v1/platform/projects", nil, nil, 401)
	page, cookies := h.call("GET", "/api/v1/platform/projects?limit=1", nil, []*http.Cookie{session}, 200)
	if len(cookies) != 0 {
		t.Fatal("catalog read changed session cookie")
	}
	seen := make(map[string]bool)
	for range 3 {
		var projects []map[string]json.RawMessage
		if err := json.Unmarshal(page["projects"], &projects); err != nil || len(projects) != 1 {
			t.Fatal("bounded catalog page", err)
		}
		id := operatorField(t, projects[0], "id")
		if seen[id] || len(projects[0]) != 10 {
			t.Fatal("duplicate page entry or unsafe DTO")
		}
		seen[id] = true
		card, issued := h.call("GET", "/api/v1/platform/projects/"+id, nil, []*http.Cookie{session}, 200)
		if operatorField(t, card, "id") != id || len(card) != 10 || len(issued) != 0 {
			t.Fatal("card or cookie mismatch")
		}
		encoded, err := json.Marshal(card)
		if err != nil || strings.Contains(string(encoded), "hidden:credential:ref") || strings.Contains(string(encoded), "auth_hidden_fixture") {
			t.Fatal("private storage binding exposed")
		}
		var next string
		if err := json.Unmarshal(page["nextCursor"], &next); err != nil {
			t.Fatal(err)
		}
		if len(seen) < 3 {
			if next == "" {
				t.Fatal("missing exclusive next cursor")
			}
			h.call("GET", "/api/v1/platform/projects?phase=ready&before="+url.QueryEscape(next), nil, []*http.Cookie{session}, 400)
			page, _ = h.call("GET", "/api/v1/platform/projects?limit=1&before="+url.QueryEscape(next), nil, []*http.Cookie{session}, 200)
		} else if next != "" {
			t.Fatal("unexpected cursor past final page")
		}
	}
	filtered, _ := h.call("GET", "/api/v1/platform/projects?phase=failed", nil, []*http.Cookie{session}, 200)
	var projects []map[string]json.RawMessage
	if err := json.Unmarshal(filtered["projects"], &projects); err != nil || len(projects) != 1 || operatorField(t, projects[0], "phase") != "failed" {
		t.Fatal("phase filter", err)
	}
	for _, query := range []string{"limit=0", "limit=101", "phase=unknown", "before=invalid", "actor=forged", "limit=1&limit=2"} {
		h.call("GET", "/api/v1/platform/projects?"+query, nil, []*http.Cookie{session}, 400)
	}
	invalidIDCursor := base64.RawURLEncoding.EncodeToString([]byte("1||2026-10-18T00:00:00Z|invalid"))
	h.call("GET", "/api/v1/platform/projects?before="+url.QueryEscape(invalidIDCursor), nil, []*http.Cookie{session}, 400)
	h.call("GET", "/api/v1/platform/projects/invalid", nil, []*http.Cookie{session}, 400)
	h.call("GET", "/api/v1/platform/projects/44444444-4444-4444-8444-444444444444", nil, []*http.Cookie{session}, 404)
	if err := admin.QueryRow(ctx, `SELECT to_jsonb(s)::text FROM auth.sessions s WHERE token_hash=$1`, hash).Scan(&after); err != nil || before != after {
		t.Fatal("catalog reads changed session state", err)
	}
	if _, err := admin.Exec(ctx, `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.projects.read'`, user); err != nil {
		t.Fatal(err)
	}
	h.call("GET", "/api/v1/auth/me", nil, []*http.Cookie{session}, 200)
	h.call("GET", "/api/v1/platform/projects", nil, []*http.Cookie{session}, 403)
	h.call("GET", "/api/v1/platform/projects/11111111-1111-4111-8111-111111111111", nil, []*http.Cookie{session}, 403)
	h.call("GET", "/api/v1/platform/projects/44444444-4444-4444-8444-444444444444", nil, []*http.Cookie{session}, 403)
	if _, err := admin.Exec(ctx, `INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES($1,'platform.projects.read')`, user); err != nil {
		t.Fatal(err)
	}
	h.call("GET", "/api/v1/platform/projects", nil, []*http.Cookie{session}, 200)
}
