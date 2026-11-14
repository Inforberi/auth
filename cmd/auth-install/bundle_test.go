package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallationBundleReuse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "installation")
	args := []string{"-dir", dir, "-name", "auth-fixture", "-origin", "https://auth.example.test", "-smtp-host", "smtp.example.test", "-smtp-from", "auth@example.test"}
	var output bytes.Buffer
	if err := run(args, &output); err != nil {
		t.Fatal(err)
	}
	runtime := filepath.Join(dir, "runtime.env")
	before, err := os.ReadFile(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(before), "auth_owner") || !strings.Contains(string(before), "AUTH_INSTALL_CLOSED_PROFILE=true") {
		t.Fatal("runtime authority or profile is incorrect")
	}
	if err := run(args, &output); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(runtime)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("repeated install changed runtime secrets", err)
	}
	for _, line := range strings.Split(string(before), "\n") {
		if _, value, ok := strings.Cut(line, "="); ok && len(value) > 32 && strings.Contains(output.String(), value) {
			t.Fatal("installer exposed a value")
		}
	}
	if err := os.Chmod(runtime, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(args, &output); err == nil {
		t.Fatal("accepted files with unsafe permissions")
	}
}
