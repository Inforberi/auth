package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRestoreDoesNotReopenAuth(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash unavailable")
	}
	source, err := os.ReadFile("postgres-restore.sh")
	if err != nil {
		t.Fatal(err)
	}
	invalidation, err := os.ReadFile("../restore-auth-state.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"", "verify", "restore", "migrate", "invalidation", "healthcheck"} {
		t.Run("failure="+failure, func(t *testing.T) {
			root := t.TempDir()
			write := func(path, contents string, mode os.FileMode) {
				t.Helper()
				path = filepath.Join(root, path)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(contents), mode); err != nil {
					t.Fatal(err)
				}
			}
			write("deploy/scripts/postgres-restore.sh", string(source), 0o700)
			write("deploy/runtime-grants.sql", "-- synthetic grants\n", 0o600)
			write("deploy/restore-auth-state.sql", string(invalidation), 0o600)
			write("synthetic.env", "APP_NAME=auth_restore_test\nPOSTGRES_DB=auth_restore_test\n", 0o600)
			write("bin/docker", `#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >> "$RESTORE_TEST_LOG"
case "$*" in
  *' ps --status running --services') printf 'api\nbackup\n' ;;
  *' backup verify '*) [[ "$RESTORE_TEST_FAIL" != verify ]] || exit 7 ;;
  *' backup restore '*) [[ "$RESTORE_TEST_FAIL" != restore ]] || exit 7 ;;
  *' migrate up') [[ "$RESTORE_TEST_FAIL" != migrate ]] || exit 7 ;;
  *'psql -X '*) [[ "$RESTORE_TEST_FAIL" != invalidation ]] || exit 7; while IFS= read -r line; do :; done ;;
  *' healthcheck-unlocked-standalone') [[ "$RESTORE_TEST_FAIL" != healthcheck ]] || exit 7 ;;
  *' exec -T postgres '*) while IFS= read -r line; do :; done ;;
esac
`, 0o700)
			log := filepath.Join(root, "docker.log")
			command := exec.CommandContext(t.Context(), "bash", filepath.Join(root, "deploy/scripts/postgres-restore.sh"))
			command.Env = []string{
				"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"),
				"AUTH_ENV_FILE=" + filepath.Join(root, "synthetic.env"),
				"RESTORE_FILE=synthetic.dump", "RESTORE_CONFIRM=auth_restore_test:auth_restore_test",
				"RESTORE_TEST_LOG=" + log, "RESTORE_TEST_FAIL=" + failure,
			}
			output, err := command.CombinedOutput()
			if (err == nil) != (failure == "") {
				t.Fatal("unexpected restore result", err, string(output))
			}
			data, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			calls := string(data)
			if strings.Contains(calls, "up -d --no-deps api") || strings.Contains(calls, "start api") {
				t.Fatal("restored credentials exposed", calls)
			}
			if !strings.Contains(calls, "rm auth_restore_test-restore-operation") {
				t.Fatal("operation lock leaked", calls)
			}
			if failure == "" {
				if !strings.Contains(string(output), "API remains stopped") || !strings.Contains(calls, "up -d --no-deps backup") {
					t.Fatal("missing manual recovery gate", string(output), calls)
				}
				stop := strings.Index(calls, "stop api migrate backup")
				restore := strings.Index(calls, "backup restore synthetic.dump")
				invalidate := strings.Index(calls, "psql -X -v ON_ERROR_STOP=1")
				health := strings.Index(calls, "healthcheck-unlocked-standalone")
				if stop < 0 || restore <= stop || invalidate <= restore || health <= invalidate {
					t.Fatal("restore preceded shutdown", calls)
				}
			} else if strings.Contains(calls, "up -d") || strings.Contains(string(output), "restore verified") {
				t.Fatal("failure resumed services or reported success", calls, string(output))
			}
		})
	}
}
