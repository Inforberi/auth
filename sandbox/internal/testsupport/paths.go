package testsupport

import (
	"path/filepath"
	"runtime"
	"testing"
)

func repositoryRoot(t interface {
	Helper()
	Fatal(...any)
},
) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate sandbox test support")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
}

func SandboxDirectory(t *testing.T) string {
	t.Helper()
	root := repositoryRoot(t)
	return filepath.Join(root, "tmp", "sandbox")
}
