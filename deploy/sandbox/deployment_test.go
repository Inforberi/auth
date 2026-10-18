package sandbox_test

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

func rotationPhase(t *testing.T, dir, name, kid, private string, keys []any) string {
	t.Helper()
	jwks := filepath.Join(dir, name+"-jwks.json")
	writeJSON(t, jwks, map[string]any{"keys": keys})
	mount := func(source, target string) map[string]any {
		return map[string]any{
			"type": "bind", "source": source, "target": target,
			"read_only": true, "bind": map[string]bool{"create_host_path": false},
		}
	}
	path := filepath.Join(dir, name+"-compose.json")
	writeJSON(t, path, map[string]any{"services": map[string]any{"api": map[string]any{
		"environment": map[string]string{"JWT_SIGNING_KEY_ID": kid, "JWT_ACCESS_TTL": "3m"},
		"volumes":     []any{mount(private, "/sandbox/jwt/private.pem"), mount(jwks, "/sandbox/jwt/jwks.json")},
	}}})
	return path
}

func redeploySandboxAPI(t *testing.T, client *http.Client, override string) {
	t.Helper()
	_ = sandboxContainer(t, "api")
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	args := []string{
		"compose", "--project-directory", root, "--env-file", ".env.example", "-p", "auth-sandbox",
		"-f", "deploy/compose.base.yml", "-f", "deploy/compose.sandbox.yml", "-f", "deploy/compose.sandbox-jwt.yml",
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
	waitReadiness(t, client, http.StatusOK)
}

func assertKeyIDs(t *testing.T, client *http.Client, expected ...string) {
	t.Helper()
	var jwks struct {
		Keys []struct {
			ID      string          `json:"kid"`
			Private json.RawMessage `json:"d"`
		} `json:"keys"`
	}
	request(t, client, "GET", "/.well-known/jwks.json", nil, &jwks, 200)
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
