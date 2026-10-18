package sandbox_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

type cleanupPolicy struct {
	Version int64
	Policy  struct{ EmailReservationDays, SessionDays, SecurityAuditDays int }
}

func TestCleanupAcceptance(t *testing.T) {
	if os.Getenv("AUTH_SANDBOX_CLEANUP") != "1" {
		t.Skip("explicit worker backlog/HTTP acceptance; run task sandbox:cleanup")
	}
	container := sandboxContainer(t, "postgres")
	apiContainer := sandboxContainer(t, "api")
	output, err := exec.CommandContext(t.Context(), "docker", "inspect", "--format", "{{json .Config.Env}}", apiContainer).Output()
	var env []string
	if err != nil || json.Unmarshal(output, &env) != nil || !slices.Contains(env, "RETENTION_BATCH_SIZE=200") || !slices.Contains(env, "RETENTION_INTERVAL=1m") {
		t.Fatal("cleanup measurement requires the original batch200/interval1m profile")
	}
	api, _ := sandboxClient(t, false)
	admin, user := adminLogin(t), userLogin(t)
	var policy cleanupPolicy
	request(t, admin, "GET", "/api/v1/admin/auth/settings/retention", nil, &policy, 200, "Origin", sandboxURL)
	if policy.Version < 1 || policy.Policy.SessionDays != 30 || policy.Policy.SecurityAuditDays != 180 {
		t.Fatal("cleanup fixture requires saved session30/audit180-day policy; not changing it")
	}
	owner := adminCommand(t)
	initial := seedCleanupFixture(t, container, owner)
	if initial != (cleanupCounts{Expired: 450, Young: 12, Live: 12, Held: 12, Families: 12, OldAudit: 450, YoungAudit: 12}) {
		t.Fatal("cleanup fixture did not commit the exact bounded initial dataset")
	}
	state, stop := startCleanupObserver(t, container, owner, initial)
	defer stop()
	secret, err := os.ReadFile(filepath.Join(sandboxDirectory(t), "jwt/consumer-secret"))
	if err != nil || len(secret) != 43 {
		t.Fatal("missing synthetic introspection credential")
	}
	input := loadInputs{cookie: loadCookie(t, user), adminCookie: loadCookie(t, admin), basic: "Basic " + base64.StdEncoding.EncodeToString(append([]byte("sandbox-consumer:"), secret...))}
	for phase := range 3 {
		t.Logf("cleanup HTTP window %d/3, 50RPS for 90s; actual worker ticks, no manual purge", phase+1)
		runLoadPhase(t, api, user, input, "cleanup", 50, 90*time.Second)
	}
	stop() // Closing done synchronizes the observer state before assertions; safe to repeat in defer.
	if state.err != nil {
		t.Fatal(state.err)
	}
	if state.last.Expired != 0 || state.last.OldAudit != 0 || state.sessionsDrainedAfter == 0 || state.auditDrainedAfter == 0 {
		t.Fatal("scoped backlog did not drain inside the 270s observation window")
	}
	request(t, user, "GET", "/api/v1/auth/me", nil, nil, 200)
	request(t, admin, "GET", "/api/v1/auth/me", nil, nil, 200)
	var after cleanupPolicy
	request(t, admin, "GET", "/api/v1/admin/auth/settings/retention", nil, &after, 200, "Origin", sandboxURL)
	if after != policy {
		t.Fatal("saved retention policy changed during acceptance")
	}
	t.Logf("worker drain: sessions=%s audit=%s snapshots=%d maxObservedDeletions=%d/%d per-table; controls preserved", state.sessionsDrainedAfter.Round(time.Millisecond), state.auditDrainedAfter.Round(time.Millisecond), state.samples, state.maxSessions, state.maxAudit)
}
