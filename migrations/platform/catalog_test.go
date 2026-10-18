package platform_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
)

const firstID domain.ID = "1c82c477-3a57-4823-8c49-a476550d8a21"

func catalogFixture(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("AUTH_PLATFORM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires the dedicated disposable auth_platform_test database")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil || cfg.ConnConfig.Database != "auth_platform_test" || cfg.ConnConfig.User != "auth" ||
		(cfg.ConnConfig.Host != "127.0.0.1" && cfg.ConnConfig.Host != "localhost" && cfg.ConnConfig.Host != "/var/run/postgresql") {
		t.Fatal("refusing non-dedicated platform fixture")
	}
	cfg.MaxConns = 4
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	t.Cleanup(cancel)
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("cannot open dedicated platform fixture")
	}
	t.Cleanup(db.Close)
	var clean bool
	if err := db.QueryRow(ctx, `SELECT to_regnamespace('auth') IS NULL AND to_regnamespace('platform') IS NULL`).Scan(&clean); err != nil || !clean {
		t.Fatal("fixture must not contain Auth or platform schemas")
	}
	up, err := os.ReadFile("000001_catalog.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, "BEGIN;"+string(up)+"COMMIT;"); err != nil {
		t.Fatal("platform migration failed")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer stop()
		down, err := os.ReadFile("000001_catalog.down.sql")
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := db.Exec(cleanup, "BEGIN;"+string(down)+"COMMIT;"); err != nil {
			t.Error("platform down migration failed")
			return
		}
		if err := db.QueryRow(cleanup, `SELECT to_regnamespace('platform') IS NULL AND to_regnamespace('auth') IS NULL`).Scan(&clean); err != nil || !clean {
			t.Error("platform migration leaked a schema or altered Auth")
		}
	})
	return db, ctx
}

func TestPlatformCatalogPostgres(t *testing.T) {
	db, ctx := catalogFixture(t)
	repo := catalog.New(db)
	insert := `INSERT INTO platform.projects(id,slug,name,origin,storage_target,created_at,updated_at)
		VALUES($1::uuid,$2,$3,$4,'primary','2026-10-18T00:00:00Z','2026-10-18T00:00:00Z')`
	if _, err := db.Exec(ctx, insert, firstID, "shop", "Магазин", "https://shop.auth.example"); err != nil {
		t.Fatal(err)
	}
	p, err := repo.Read(ctx, firstID)
	if err != nil || p.Phase != domain.Pending || p.DesiredState != domain.Enabled || p.AdmitsRequests() || p.Version != 1 || p.Generation != 1 {
		t.Fatalf("unexpected initial project: %+v, %v", p, err)
	}
	for _, origin := range []string{p.Origin, "https://unknown.auth.example"} {
		if _, err := repo.Resolve(ctx, origin); !errors.Is(err, domain.ErrNotFound) {
			t.Fatal("pending/unknown project admitted")
		}
	}
	t.Run("constraints", func(t *testing.T) {
		for _, test := range []struct{ query, code string }{
			{`UPDATE platform.projects SET phase='ready'`, "23514"},
			{`UPDATE platform.projects SET phase='unknown'`, "23514"},
			{`UPDATE platform.projects SET desired_state='unknown'`, "23514"},
			{`UPDATE platform.projects SET version=0`, "23514"},
			{`UPDATE platform.projects SET generation=0`, "23514"},
			{`UPDATE platform.projects SET name=repeat('я',101)`, "23514"},
			{`UPDATE platform.projects SET slug='console'`, "23514"},
			{`UPDATE platform.projects SET credential_ref='postgres://secret@host/database'`, "23514"},
		} {
			_, err := db.Exec(ctx, test.query)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != test.code {
				t.Fatalf("expected constraint refusal for %s", test.query)
			}
		}
		_, err := db.Exec(ctx, insert, "ed5f1807-4d0a-4c53-a3e3-b8bd5a221cc1", "other", "Other", p.Origin)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
			t.Fatal("origin collision accepted")
		}
	})
	t.Run("admission", func(t *testing.T) {
		if _, err := db.Exec(ctx, `UPDATE platform.projects SET phase='ready',database_name='auth_shop',credential_ref='project:shop:db:v1',schema_version=1`); err != nil {
			t.Fatal(err)
		}
		b, err := repo.Resolve(ctx, p.Origin)
		if err != nil || b.Project.ID != firstID || !b.Project.AdmitsRequests() || b.CredentialRef != "project:shop:db:v1" || b.SchemaVersion != 1 {
			t.Fatal("ready binding not resolved")
		}
		if _, err := db.Exec(ctx, `UPDATE platform.projects SET desired_state='suspended',version=version+1`); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Resolve(ctx, p.Origin); !errors.Is(err, domain.ErrNotFound) {
			t.Fatal("suspended project admitted from stale state")
		}
		if _, err := db.Exec(ctx, `UPDATE platform.projects SET desired_state='enabled',phase='failed',version=version+1`); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Resolve(ctx, p.Origin); !errors.Is(err, domain.ErrNotFound) {
			t.Fatal("failed project admitted")
		}
	})
	t.Run("pagination", func(t *testing.T) {
		for _, entry := range []struct{ id, slug string }{
			{"ed5f1807-4d0a-4c53-a3e3-b8bd5a221cc1", "other"},
			{"fd5f1807-4d0a-4c53-a3e3-b8bd5a221cc1", "third"},
		} {
			if _, err := db.Exec(ctx, insert, entry.id, entry.slug, entry.slug, "https://"+entry.slug+".auth.example"); err != nil {
				t.Fatal(err)
			}
		}
		page, err := repo.List(ctx, catalog.ListQuery{Limit: 2})
		if err != nil || len(page.Projects) != 2 || page.Next == nil {
			t.Fatal("missing bounded first page")
		}
		next, err := repo.List(ctx, catalog.ListQuery{Limit: 2, Before: page.Next})
		if err != nil || len(next.Projects) != 1 || next.Next != nil || next.Projects[0].ID != firstID {
			t.Fatal("timestamp tie pagination skipped or repeated projects")
		}
		filtered, err := repo.List(ctx, catalog.ListQuery{Limit: 2, Phase: domain.Pending})
		if err != nil || len(filtered.Projects) != 2 || filtered.Next != nil {
			t.Fatal("phase filter mismatch")
		}
		unknown, err := repo.List(ctx, catalog.ListQuery{Limit: 1, Phase: domain.Provisioning})
		if err != nil || len(unknown.Projects) != 0 || unknown.Next != nil {
			t.Fatal("empty page is not stable")
		}
	})
	t.Run("indexes", func(t *testing.T) {
		_, err := db.Exec(ctx, `INSERT INTO platform.projects(id,slug,name,origin,storage_target,phase,database_name,credential_ref,schema_version)
			SELECT ('00000000-0000-0000-0001-'||lpad(n::text,12,'0'))::uuid,'fixture-'||n,'Fixture '||n,
			'https://fixture-'||n||'.auth.example','primary','ready','auth_fixture_'||n,'fixture:'||n,1 FROM generate_series(1,2048) n;
			ANALYZE platform.projects`)
		if err != nil {
			t.Fatal(err)
		}
		for _, test := range []struct{ query, index string }{
			{`SELECT id FROM platform.projects WHERE origin='https://shop.auth.example' AND desired_state='enabled' AND phase='ready'`, "projects_origin_key"},
			{`SELECT id FROM platform.projects ORDER BY created_at DESC,id DESC LIMIT 2`, "projects_page"},
		} {
			var plan string
			if err := db.QueryRow(ctx, "EXPLAIN (FORMAT JSON) "+test.query).Scan(&plan); err != nil || !strings.Contains(plan, test.index) {
				t.Fatalf("expected selective index %s", test.index)
			}
		}
	})
	t.Run("no public grants", func(t *testing.T) {
		var exposed bool
		err := db.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a
			WHERE n.nspname='platform' AND a.grantee=0
		) OR EXISTS (
			SELECT 1 FROM pg_class r JOIN pg_namespace n ON n.oid=r.relnamespace
			CROSS JOIN LATERAL aclexplode(r.relacl) a
			WHERE n.nspname='platform' AND r.relname='projects' AND a.grantee=0
		)`).Scan(&exposed)
		if err != nil || exposed {
			t.Fatal("catalog exposed through PUBLIC grants")
		}
	})
	t.Run("cancellation", func(t *testing.T) {
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := repo.Read(cancelled, firstID); !errors.Is(err, domain.ErrUnavailable) || !errors.Is(err, context.Canceled) {
			t.Fatal("catalog failure did not preserve safe cancellation")
		}
		if db.Stat().AcquiredConns() != 0 {
			t.Fatal("catalog read leaked an acquired connection")
		}
	})
}
