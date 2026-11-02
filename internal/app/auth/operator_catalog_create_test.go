package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	operatorpostgres "github.com/Inforberi/financial-intelligence/internal/admin/administrators/repository/postgres"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
)

func creationInput(n int, slug string) projectdomain.Create {
	return projectdomain.Create{OperationID: projectdomain.ID(fmt.Sprintf("80000000-0000-4000-8000-%012d", n)), Slug: slug, Name: " New project ", Reason: "fixture-creation"}
}

func operatorCatalogCreateDrill(t *testing.T, admin, runtime *pgxpool.Pool, authority *operatorpostgres.Repository, h *operatorHTTPS, actor operatordomain.Principal, session *http.Cookie) {
	t.Helper()
	ctx := t.Context()
	cookies := []*http.Cookie{session}
	call := func(input projectdomain.Create, expected int) map[string]json.RawMessage {
		t.Helper()
		body := map[string]any{"operationId": input.OperationID, "slug": input.Slug, "name": input.Name, "reason": input.Reason}
		result, issued := h.call("POST", "/api/v1/platform/projects", body, cookies, expected)
		if len(issued) != 0 {
			t.Fatal("creation changed cookies")
		}
		return result
	}
	input := creationInput(1, "new-project")
	h.call("POST", "/api/v1/platform/projects", nil, nil, 401)
	first := call(input, 201)
	var project map[string]json.RawMessage
	if err := json.Unmarshal(first["project"], &project); err != nil || len(project) != 10 {
		t.Fatal("unsafe creation DTO", err)
	}
	id := operatorField(t, project, "id")
	if !projectdomain.ValidID(projectdomain.ID(id)) || operatorField(t, project, "origin") != "https://new-project.auth.example" || operatorField(t, project, "name") != "New project" || operatorField(t, project, "phase") != "pending" || string(project["version"]) != "1" {
		t.Fatal("invalid initial project snapshot")
	}
	var pending bool
	if err := admin.QueryRow(ctx, `SELECT storage_target='primary' AND database_name IS NULL AND credential_ref IS NULL AND schema_version=0
		AND phase='pending' AND desired_state='enabled' AND version=1 AND generation=1 FROM platform.projects WHERE id=$1`, id).Scan(&pending); err != nil || !pending {
		t.Fatal("creation provisioned unexpected storage", err)
	}
	h.call("POST", "/api/v1/platform/projects/"+id+"/suspend", map[string]any{"operationId": "89999999-9999-4999-8999-999999999999", "expectedVersion": 1, "expectedGeneration": 1, "reason": "fixture-suspend"}, cookies, 200)
	replay := call(input, 200)
	if string(replay["replayed"]) != "true" || string(replay["project"]) != string(first["project"]) {
		t.Fatal("creation replay lost original snapshot")
	}
	card, _ := h.call("GET", "/api/v1/platform/projects/"+id, nil, cookies, 200)
	if string(card["version"]) != "2" || operatorField(t, card, "desiredState") != "suspended" {
		t.Fatal("replay reset lifecycle")
	}
	changed := input
	changed.Name = "Other"
	call(changed, 409)
	call(creationInput(2, input.Slug), 409)
	for _, invalid := range []projectdomain.Create{creationInput(3, "api"), creationInput(3, "Upper"), {OperationID: "invalid", Slug: "valid", Name: "Name", Reason: "incident"}} {
		call(invalid, 400)
	}
	h.call("POST", "/api/v1/platform/projects", map[string]any{"origin": "https://elsewhere.example"}, cookies, 400)
	if _, err := admin.Exec(ctx, `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.projects.manage'`, actor.UserID); err != nil {
		t.Fatal(err)
	}
	call(input, 403)
	if _, err := admin.Exec(ctx, `INSERT INTO platform.operator_permissions VALUES($1,'platform.projects.manage')`, actor.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp()-interval '6 minutes' WHERE token_hash=$1`, actor.TokenHash); err != nil {
		t.Fatal(err)
	}
	call(input, 428)
	if _, err := admin.Exec(ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp() WHERE token_hash=$1`, actor.TokenHash); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `ALTER TABLE platform.project_creations ADD CONSTRAINT fixture_creation_audit CHECK(slug<>'audit-failure') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	call(creationInput(4, "audit-failure"), 503)
	if _, err := admin.Exec(ctx, `ALTER TABLE platform.project_creations DROP CONSTRAINT fixture_creation_audit`); err != nil {
		t.Fatal(err)
	}
	var clean bool
	if err := admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM platform.projects WHERE slug='audit-failure')
		AND NOT EXISTS(SELECT 1 FROM platform.project_creations WHERE slug='audit-failure')`).Scan(&clean); err != nil || !clean {
		t.Fatal("creation audit failure left partial data", err)
	}
	manager, err := projectpostgres.NewManaged(runtime, authority, 5*time.Minute, projectdomain.CreationPolicy{AuthDomain: "auth.example", StorageTarget: "primary", PlatformOrigin: "https://console.auth.example"})
	if err != nil {
		t.Fatal(err)
	}
	operatorCreationConcurrency(t, admin, manager, actor)
	// A changed deployment policy must not reinterpret an already committed operation.
	reconfigured, err := projectpostgres.NewManaged(runtime, authority, 5*time.Minute, projectdomain.CreationPolicy{AuthDomain: "other.example", StorageTarget: "secondary", PlatformOrigin: "https://console.auth.example"})
	if err != nil {
		t.Fatal(err)
	}
	previous, err := reconfigured.Create(ctx, actor, input)
	if err != nil || !previous.Replayed || previous.Project.ID != projectdomain.ID(id) || previous.Project.Origin != "https://new-project.auth.example" {
		t.Fatal("replay changed with deployment config", err)
	}
}

func operatorCreationConcurrency(t *testing.T, admin *pgxpool.Pool, manager *projectpostgres.Repository, actor operatordomain.Principal) {
	t.Helper()
	ctx := t.Context()
	type outcome struct {
		receipt projectdomain.CreationReceipt
		err     error
	}
	for _, sameOperation := range []bool{true, false} {
		results := make(chan outcome, 4)
		base := 10
		slug := "parallel-same-operation"
		if !sameOperation {
			base = 20
			slug = "parallel-same-slug"
		}
		for i := range 4 {
			command := creationInput(base, slug)
			if !sameOperation {
				command.OperationID = creationInput(base+i, slug).OperationID
			}
			go func() { r, err := manager.Create(ctx, actor, command); results <- outcome{r, err} }()
		}
		created, replayed, conflicts := 0, 0, 0
		var id projectdomain.ID
		for range 4 {
			result := <-results
			switch {
			case errors.Is(result.err, projectdomain.ErrConflict):
				conflicts++
			case result.err != nil:
				t.Fatal(result.err)
			default:
				if id != "" && id != result.receipt.Project.ID {
					t.Fatal("duplicate project for one intent")
				}
				id = result.receipt.Project.ID
				if result.receipt.Replayed {
					replayed++
				} else {
					created++
				}
			}
		}
		if created != 1 || (sameOperation && replayed != 3) || (!sameOperation && conflicts != 3) {
			t.Fatal("incorrect concurrent creation", created, replayed, conflicts)
		}
		var count int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM platform.project_creations WHERE slug=$1`, slug).Scan(&count); err != nil || count != 1 {
			t.Fatal("duplicate creation audit", count, err)
		}
	}
	blocker, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	command := creationInput(30, "cancelled-create")
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('platform.project.create:'||$1::text,0))`, command.OperationID); err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	_, err = manager.Create(bounded, actor, command)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("operation wait is unbounded", err)
	}
	// A different operation can commit while the first operation lock is held.
	if _, err := manager.Create(ctx, actor, creationInput(31, "independent-create")); err != nil {
		t.Fatal("independent creation blocked", err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if result, err := manager.Create(ctx, actor, command); err != nil || result.Replayed {
		t.Fatal("cancelled creation left a receipt/transaction", err)
	}
}
