package admin_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	adminapp "github.com/Inforberi/financial-intelligence/internal/app/admin"
	authapp "github.com/Inforberi/financial-intelligence/internal/app/auth"
	appfixtures "github.com/Inforberi/financial-intelligence/internal/app/tests/fixtures"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

func TestOperatorRejectsForeignScopeBeforeSQL(t *testing.T) {
	cfg := appfixtures.OperatorConfig("1c82c477-3a57-4823-8c49-a476550d8a21")
	project, err := realmscope.New("project", cfg.Platform.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	other, err := realmscope.New("platform", "2c82c477-3a57-4823-8c49-a476550d8a21")
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []realmscope.Scope{{}, realmscope.Legacy(), project, other} {
		// Invalid scopes must fail before these intentionally unusable adapters are touched.
		deps := authapp.Dependencies{Pool: &pgxpool.Pool{}, Redis: &redis.Client{}, Logger: zap.NewNop(), Hash: &hasher.Bounded{}, Scope: scope}
		if result, err := adminapp.Assemble(t.Context(), cfg, deps, &operatorMailbox{}); result != nil || err == nil {
			t.Fatal("operator accepted missing/foreign scope")
		}
	}
}
