package sandbox_test

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

//go:embed cleanup_fixture.sql
var cleanupFixtureSQL string

type cleanupCounts struct{ Expired, Young, Live, Held, Families, OldAudit, YoungAudit int }

const cleanupCountSQL = `SELECT json_build_object(
 'expired',count(*) FILTER (WHERE user_agent='sandbox-cleanup-expired'),
 'young',count(*) FILTER (WHERE user_agent='sandbox-cleanup-young'),
 'live',count(*) FILTER (WHERE user_agent='sandbox-cleanup-live'),
 'held',count(*) FILTER (WHERE user_agent='sandbox-cleanup-held'),
 'families',(SELECT count(*) FROM auth.refresh_families f JOIN auth.sessions s ON s.id=f.session_id WHERE s.user_id=:'owner'),
 'oldAudit',(SELECT count(*) FROM auth.password_audit WHERE user_id=:'owner' AND created_at<clock_timestamp()-interval '180 days'),
 'youngAudit',(SELECT count(*) FROM auth.password_audit WHERE user_id=:'owner' AND created_at>clock_timestamp()-interval '180 days'))
 FROM auth.sessions WHERE user_id=:'owner';`

func cleanupSQL(ctx context.Context, container, owner, query string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", container, "psql", "-X", "-U", "auth", "-d", "auth", "-qAt", "-v", "ON_ERROR_STOP=1", "-v", "owner="+owner, "-f", "-")
	cmd.Stdin = strings.NewReader("SET statement_timeout='5s'; SET lock_timeout='1s';\n" + query)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("sandbox fixture SQL: %w: %.2048s", err, output)
	}
	return output, nil
}

func readCleanupCounts(ctx context.Context, container, owner string) (cleanupCounts, error) {
	var counts cleanupCounts
	output, err := cleanupSQL(ctx, container, owner, cleanupCountSQL)
	if err != nil {
		return counts, err
	}
	err = json.Unmarshal(output, &counts)
	return counts, err
}

func seedCleanupFixture(t *testing.T, container, owner string) cleanupCounts {
	t.Helper()
	output, err := cleanupSQL(t.Context(), container, owner, cleanupFixtureSQL+"\n"+cleanupCountSQL+"\nCOMMIT;")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// This fresh UUID was inserted successfully by this test, never an existing account.
		query := `BEGIN;
 DELETE FROM auth.refresh_families f USING auth.sessions s WHERE f.session_id=s.id AND s.user_id=:'owner';
 DELETE FROM auth.sessions WHERE user_id=:'owner';
 DELETE FROM auth.password_audit WHERE user_id=:'owner';
 DELETE FROM auth.users WHERE id=:'owner' AND status='blocked'; COMMIT;`
		if _, err := cleanupSQL(context.WithoutCancel(t.Context()), container, owner, query); err != nil {
			t.Error(err)
			return
		}
		output, err := cleanupSQL(context.WithoutCancel(t.Context()), container, owner, `SELECT EXISTS(SELECT 1 FROM auth.users WHERE id=:'owner');`)
		if err != nil || strings.TrimSpace(string(output)) != "f" {
			t.Error("synthetic cleanup owner was not removed")
		}
	})
	t.Logf("isolated blocked fixture owner: %s; no credentials or contact", owner)
	var counts cleanupCounts
	if err := json.Unmarshal(output, &counts); err != nil {
		t.Fatal("invalid atomic cleanup fixture snapshot")
	}
	return counts
}
