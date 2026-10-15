package postgres

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	accessapp "github.com/Inforberi/financial-intelligence/internal/app/access"
)

func checkAccessCatalog(t *testing.T, db *pgxpool.Pool, ctx context.Context, existing accessdomain.Role) {
	t.Helper()
	if _, err := accessapp.New(ctx, db, settings.Config{}); !errors.Is(err, accessdomain.ErrConflict) {
		t.Fatalf("undeclared existing permission accepted: %v", err)
	}
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"permissions":[{"key":"reports.read","name":"Read reports"}],"roleTemplates":[{"key":"report_reader","name":"Template only","permissions":[]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var beforeRoles, beforeAssignments, beforeAudit int
	if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM auth.roles),(SELECT count(*) FROM auth.user_roles),(SELECT count(*) FROM auth.access_audit)`).Scan(&beforeRoles, &beforeAssignments, &beforeAudit); err != nil {
		t.Fatal(err)
	}
	app, err := accessapp.New(ctx, db, settings.Config{CatalogFile: path})
	if err != nil {
		t.Fatal(err)
	}
	permissions := app.Service.Catalog()
	if len(app.Templates()) != 1 || len(permissions) != 6 || permissions[5].Key != "reports.read" {
		t.Fatal("catalog assembly lost definitions")
	}
	role, err := app.Service.ReadRole(ctx, existing.ID)
	if err != nil || role.Name == "Template only" || len(role.Permissions) != 1 {
		t.Fatalf("template overwrote role: %+v %v", role, err)
	}
	var roles, assignments, audit int
	if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM auth.roles),(SELECT count(*) FROM auth.user_roles),(SELECT count(*) FROM auth.access_audit)`).Scan(&roles, &assignments, &audit); err != nil || roles != beforeRoles || assignments != beforeAssignments || audit != beforeAudit {
		t.Fatal("catalog assembly mutated access data")
	}
}
