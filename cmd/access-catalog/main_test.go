package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
)

func TestPreviewCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	data := []byte(`{"version":1,"permissions":[{"key":"reports.read","name":"Read reports"}]}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var output, diagnostics bytes.Buffer
	if err := run([]string{"-file", path}, &output, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var changes settings.Changes
	if err := json.Unmarshal(output.Bytes(), &changes); err != nil || len(changes.AddedPermissions) != 1 || changes.AddedPermissions[0] != "reports.read" {
		t.Fatalf("command output: %s %v", output.String(), err)
	}
	stored, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(stored, data) {
		t.Fatal("preview edited file")
	}
	output.Reset()
	if err := run([]string{"-file", path, "-current", path}, &output, &diagnostics); err != nil {
		t.Fatal(err)
	}
	if err := run(nil, &output, &diagnostics); err == nil {
		t.Fatal("missing path accepted")
	}
}
