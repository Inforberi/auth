package sandbox_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProductionComposeSeparatesCredentials(t *testing.T) {
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("requires Docker Compose CLI; no daemon is used")
	}
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	control, app := filepath.Join(temp, "control.env"), filepath.Join(temp, "api.env")
	runtimeURL := "postgres://auth_runtime:synthetic-runtime@postgres:5432/auth?sslmode=disable"
	controlEnv := "APP_NAME=auth-deploy-check\nPORT=8080\nPOSTGRES_DB=auth\nPOSTGRES_USER=auth_owner\nPOSTGRES_PASSWORD=synthetic-owner\nREDIS_PASSWORD=synthetic-redis\nMIGRATION_DATABASE_URL=postgres://auth_owner:synthetic-owner@postgres:5432/auth?sslmode=disable\nAUTH_SECRETS_DIR=" + temp + "\n"
	for path, contents := range map[string]string{control: controlEnv, app: "APP_ENV=prod\nDATABASE_URL=" + runtimeURL + "\nREDIS_HOST=redis\nREDIS_PASSWORD=synthetic-redis\n"} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, docker, "compose", "--project-directory", root, "--env-file", control, "-f", filepath.Join(root, "deploy/compose/base.yml"), "-f", filepath.Join(root, "deploy/compose/production.yml"), "config", "--format", "json")
	// Explicit synthetic environment prevents real shell/.env credentials from entering the model.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "APP_ENV_FILE=" + app}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("synthetic Compose config: %v\n%s", err, stderr.String())
	}
	var model struct {
		Services map[string]struct {
			Environment map[string]string `json:"environment"`
			Ports       []json.RawMessage `json:"ports"`
			ReadOnly    bool              `json:"read_only"`
			Volumes     []struct {
				Source   string `json:"source"`
				Target   string `json:"target"`
				ReadOnly bool   `json:"read_only"`
				Bind     struct {
					CreateHostPath bool `json:"create_host_path"`
				} `json:"bind"`
			} `json:"volumes"`
		} `json:"services"`
	}
	if err := json.Unmarshal(output, &model); err != nil {
		t.Fatal(err)
	}
	api, ok := model.Services["api"]
	if !ok {
		t.Fatal("missing API service")
	}
	for _, key := range []string{"POSTGRES_PASSWORD", "MIGRATION_DATABASE_URL"} {
		if _, ok := api.Environment[key]; ok {
			t.Fatalf("API received owner credential %s", key)
		}
	}
	if api.Environment["DATABASE_URL"] != runtimeURL || api.Environment["APP_ENV"] != "prod" {
		t.Fatal("API runtime configuration was not loaded")
	}
	if model.Services["postgres"].Environment["POSTGRES_PASSWORD"] != "synthetic-owner" {
		t.Fatal("Postgres did not receive its owner credential")
	}
	if !api.ReadOnly {
		t.Fatal("API filesystem must be read-only")
	}
	mounted := false
	for _, mount := range api.Volumes {
		if mount.Target == "/run/secrets" {
			mounted = mount.Source == temp && mount.ReadOnly && !mount.Bind.CreateHostPath
		}
	}
	if !mounted {
		t.Fatal("missing fail-closed read-only API files mount")
	}
	for _, name := range []string{"postgres", "redis"} {
		if len(model.Services[name].Ports) != 0 {
			t.Fatalf("%s must not publish a host port in production", name)
		}
	}
	var withoutMigration []string
	for _, line := range strings.Split(controlEnv, "\n") {
		if !strings.HasPrefix(line, "MIGRATION_DATABASE_URL=") {
			withoutMigration = append(withoutMigration, line)
		}
	}
	if err := os.WriteFile(control, []byte(strings.Join(withoutMigration, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := exec.CommandContext(ctx, docker, cmd.Args[1:]...)
	missing.Env = cmd.Env
	rejected, err := missing.CombinedOutput()
	if err == nil || !bytes.Contains(rejected, []byte("MIGRATION_DATABASE_URL")) {
		t.Fatal("missing migration owner URL must fail closed")
	}
}
