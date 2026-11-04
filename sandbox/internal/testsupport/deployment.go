package testsupport

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"
)

func EnableAdminSandbox(t *testing.T, api *http.Client) {
	t.Helper()
	AssertKeyIDs(t, api, "sandbox-1")
	dir, err := os.MkdirTemp(SandboxDirectory(t), "admin-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		RedeploySandboxAPI(t, api, "")
		if err := os.RemoveAll(dir); err != nil {
			t.Error("cannot remove generated administrative test override")
		}
	})
	override := filepath.Join(dir, "compose.json")
	WriteJSON(t, override, map[string]any{"services": map[string]any{"api": map[string]any{
		"environment": map[string]string{"INVITATIONS_ENABLED": "true", "TEMPORARY_PASSWORD_ENABLED": "true", "INVITATION_URL": SandboxURL + "/activate-account"},
	}}})
	RedeploySandboxAPI(t, api, override)
}

func RedeploySandboxAPI(t *testing.T, client *http.Client, override string) {
	t.Helper()
	_ = SandboxContainer(t, "api")
	root := repositoryRoot(t)
	args := []string{
		"compose", "--project-directory", root, "--env-file", ".env.example", "-p", "auth-sandbox",
		"-f", "deploy/compose/base.yml", "-f", "sandbox/compose.yml", "-f", "sandbox/config/jwt.yml",
	}
	if override != "" {
		args = append(args, "-f", override)
	}
	args = append(args, "up", "-d", "--no-deps", "--force-recreate", "api")
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "SANDBOX_UID="+strconv.Itoa(os.Getuid()), "SANDBOX_GID="+strconv.Itoa(os.Getgid()))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sandbox API deployment failed: %v: %s", err, output)
	}
	// A recreated API cannot have a previous process's cached readiness.
	WaitReadiness(t, client, http.StatusOK)
}

func AssertKeyIDs(t *testing.T, client *http.Client, expected ...string) {
	t.Helper()
	var jwks struct {
		Keys []struct {
			ID      string          `json:"kid"`
			Private json.RawMessage `json:"d"`
		} `json:"keys"`
	}
	Request(t, client, "GET", "/.well-known/jwks.json", nil, &jwks, 200)
	actual := make([]string, 0, len(jwks.Keys))
	for _, key := range jwks.Keys {
		if len(key.Private) != 0 {
			t.Fatal("private material in public JWKS")
		}
		actual = append(actual, key.ID)
	}
	slices.Sort(actual)
	slices.Sort(expected)
	if !slices.Equal(actual, expected) {
		t.Fatal("unexpected public key IDs")
	}
}
